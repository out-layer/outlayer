# customer-recovery

Standalone CKD recovery tool for an OutLayer per-customer vault that has gone through `finalize_recovery`.

After recovery the vault is `unlocked = true`, parent has FullAccess, and OutLayer's keystore refuses to serve any further operations bound to that vault. The customer recovers their per-vault master themselves by signing a fresh `request_app_private_key` call to the MPC contract directly.

## Why this exists

The per-vault master is derived deterministically from MPC's network secret. Anyone holding a FullAccess key on the vault account can submit `request_app_private_key` and recover the same master that OutLayer's keystore was using. This tool does that.

The only non-obvious input is `derivation_path` — it's `HMAC-SHA256(default_master, "vault-master:<vault_id>")` and was unguessable before the keystore's first MPC call. After that first call, the path appears in plaintext on chain (in the tx args), so the customer can read it from history and reuse it.

## Build

```bash
cd scripts/customer-recovery
cargo build --release
```

Binary: `target/release/customer-recovery`.

## Run

> ⚠ **Never paste your FullAccess private key on the command line.**
> CLI args end up in `~/.bash_history` / `~/.zsh_history` / `ps`
> output / shell session recordings. Pass it via the
> `VAULT_PRIVATE_KEY` env var instead — same for `MPC_PUBLIC_KEY` if
> the operator considers it sensitive in your context.

```bash
export VAULT_PRIVATE_KEY="$(cat path/to/vault-fullaccess.key)"
export MPC_PUBLIC_KEY='bls12381g2:...'

./target/release/customer-recovery \
    --vault-id vault.alice.testnet \
    --from-chain \
    --rpc-url https://rpc.testnet.fastnear.com
```

The `--signer-private-key` flag is also accepted (it reads
`VAULT_PRIVATE_KEY` automatically when omitted), but operators
running this in a terminal should prefer the env-var form. After
the run, `unset VAULT_PRIVATE_KEY` to clear it from the shell
session.

Required inputs:

| Flag | Source |
|---|---|
| `--vault-id` | Your vault sub-account |
| `--signer-private-key` | The FullAccess private key that was atomically installed by `outlayer vault finalize-recovery <vault> <new_parent_pubkey>` — typically the `private_key` half of whatever you generated via `customer-recovery generate-key` before finalize. Also accepted via `VAULT_PRIVATE_KEY` env var |
| `--mpc-public-key` | The MPC G2 public key (`bls12381g2:...`) — same value as the keystore's `MPC_PUBLIC_KEY` env var. Ask the operator or copy from `docker/.env.*-keystore-phala`. Also accepted via `MPC_PUBLIC_KEY` env var |
| `--derivation-path` OR `--from-chain` | If `--from-chain` is set, the tool queries NEARblocks for the most recent `request_app_private_key` call from your vault and extracts the path automatically. Otherwise pass it explicitly |

Defaults assume testnet. Override with `--mpc-contract`, `--mpc-domain-id`, `--rpc-url`, `--nearblocks-url` for mainnet.

## Output

```
# === Per-vault master recovered ===
# vault_id       = vault.alice.testnet
# derivation_path= a3f17c…

master_hex=4f8c…32 bytes hex…
```

This is the same 32-byte master the keystore-worker was using.

## End-to-end runbook

The full sovereign-exit procedure (initiate → wait → finalize →
recover master → derive wallet → decrypt secrets) is documented in
[`docs/LEAVING_OUTLAYER.md`](../../docs/LEAVING_OUTLAYER.md).
The wrapper script [`walkthrough.sh`](./walkthrough.sh) runs steps
1–5 of that procedure with idempotency, exit-window introspection,
and pre-flight checks. Recommended over invoking the binary
manually.

```bash
VAULT_ID=vault.alice.testnet \
MPC_PUBLIC_KEY='bls12381g2:...' \
NETWORK=testnet \
  ./walkthrough.sh
```

## Subcommands

The binary exposes three subcommands beyond the default
master-recovery flow. All are read-only locally — none of them
touch the network unless explicitly asked.

### `generate-key`

```bash
customer-recovery generate-key > new-parent.json
```

Emits a fresh ed25519 keypair as `{public_key, private_key}`
JSON (the format `near-cli-rs` keychain files use). Used in the
walkthrough to produce the new vault-owning key before `finalize_recovery`
so the user doesn't need an external NEAR keygen tool installed.

### `derive-wallet-key`

```bash
customer-recovery derive-wallet-key \
    --master <hex_64> \
    --wallet-id <uuid>
```

Re-derives the ed25519 keypair the OutLayer keystore minted for a
specific custody wallet (`POST /register {"vault_id": "..."}`).
Output JSON:

```json
{
  "wallet_id": "...",
  "near_address": "<hex>",
  "public_key": "ed25519:...",
  "private_key": "ed25519:..."
}
```

Cryptographic recipe (matches `keystore-worker/src/crypto.rs::derive_keypair`):
```
secret_bytes = HMAC-SHA256(per_vault_master, "wallet:{wallet_id}:near")[..32]
ed25519     = SigningKey::from_bytes(secret_bytes)
```

`near_address` MUST equal the `near_account_id` the coordinator
returned at `/register` time. Mismatch means the seed shape has
diverged between keystore and customer-recovery — file a bug.

### `decrypt-secret`

```bash
customer-recovery decrypt-secret \
    --master <hex_64> \
    --seed 'project:owner.near/project-name:owner.near' \
    --ciphertext-base64 'AQB...'
```

Decrypts an on-chain ciphertext locally. Auto-detects the wire
format:

| First byte | Format | Algorithm |
|---|---|---|
| `0x01` | ECIES v1 | X25519 ECDH + HKDF-SHA256(`outlayer-keystore-v1`) + ChaCha20-Poly1305 |
| anything else | Legacy ChaCha20-Poly1305 | Ed25519-verifying-key-as-symmetric (kept for backwards compatibility; broken on the keystore side, present here for completeness) |

Dashboard-stored secrets (`/dashboard/secrets`) use ECIES.
`outlayer secrets set --vault-id <vault>` uses ECIES as of
outlayer-cli v0.2 (older versions used the legacy format which
the keystore could not decrypt — re-set those secrets via current
CLI or the dashboard).

Seed format per accessor (matches the seeds the keystore builds in
`keystore-worker/src/api.rs`):

| Accessor | Seed |
|---|---|
| `Project { project_id }` | `project:<project_id>:<owner>` |
| `Repo { repo, branch: Some(b) }` | `<normalized_repo>:<owner>:<b>` |
| `Repo { repo, branch: None }` | `<normalized_repo>:<owner>` |
| `WasmHash { hash }` | `wasm_hash:<hash>:<owner>` |

Plaintext is canonical UTF-8 JSON (`{"KEY":"value", ...}`).

## Reproducing your wallet addresses

Every keypair the keystore returned through `/wallet/v1/address`,
`/wallet/v1/sign-message`, payment-check derivation, etc., comes from
a single deterministic recipe:

```
secret_bytes = HMAC-SHA256(master, seed)[..32]
ed25519_keypair = SigningKey::from_bytes(secret_bytes)
near_implicit_address = hex(verifying_key)
```

The `seed` is whichever string the keystore passed to `derive_keypair`.
Common seeds:

| Endpoint | Seed format |
|---|---|
| `GET /wallet/v1/address?chain=near` | `wallet:{wallet_id}:near` |
| `GET /wallet/v1/address?chain=eth` | `wallet:{wallet_id}:eth` |
| Payment check ephemeral | `check:{counter}` |

Your `wallet_id` came back from `POST /customer/register` (e.g.
`27487fc6-b67d-4a19-a1d7-db352c0475c5`). You can also grep the
`Set-Cookie` of any past `/wallet/v1/*` response or replay the
`X-Wallet-Id` header.

### Verification recipe

```python
# Verifies the recovered master matches the address OutLayer gave you.
# Requires: pip install pynacl
import hmac, hashlib
from nacl.signing import SigningKey

master = bytes.fromhex("d24457ae...your master_hex...")
wallet_id = "27487fc6-b67d-4a19-a1d7-db352c0475c5"
seed = f"wallet:{wallet_id}:near".encode()

secret = hmac.new(master, seed, hashlib.sha256).digest()[:32]
pubkey = bytes(SigningKey(secret).verify_key)
print(pubkey.hex())   # → matches what /wallet/v1/address returned
```

If this prints the same hex string OutLayer returned for that
`wallet_id`, the master is correct and you now control all derived
keypairs.

### Auto-discovery of `derivation_path`

The `--from-chain` flag queries NEARblocks for the most recent
direct call from your vault account that carries CKD args — it
recognises both `request_master` (the vault contract's proxy method,
the normal shape) and `request_app_private_key` (legacy direct calls
from older vaults). NEARblocks' free tier lists direct outbound txns
but not all cross-contract receipts, so the proxy variant is what
auto-discovery typically finds.

If `--from-chain` returns "no past tx", you can pull
`derivation_path` manually from the chain via NEAR RPC:

```bash
TX=<tx_hash from on-chain history>
curl -X POST https://rpc.testnet.fastnear.com -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":\"q\",\"method\":\"EXPERIMENTAL_tx_status\",
       \"params\":[\"$TX\",\"<your-vault-id>\"]}" | \
  jq -r '.result.transaction.actions[0].FunctionCall.args' | base64 -d | \
  jq -r '.request.derivation_path'
```

## Cost

A single `request_app_private_key` call costs ~150 TGas + 1 yoctoNEAR. Vault account must have a few NEAR available at call time.

## Caveats

- The tool MUST be run on a host you trust — the master is printed to stdout. Don't run it through a screen-sharing session, don't pipe the output to a logger that ships to a third party.
- Set `RUST_LOG=debug` to see verbose progress. Default is INFO.
- If `--from-chain` finds nothing, your vault has never derived a master through OutLayer (no keystore ever ran CKD against it). In that case, there's also nothing to recover — no per-vault secret was ever generated.
