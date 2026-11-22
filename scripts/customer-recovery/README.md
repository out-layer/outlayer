# customer-recovery

Standalone CKD recovery tool for an OutLayer per-customer vault that has gone through `finalize_recovery`.

After recovery the vault is `unlocked = true`, the key you passed to `finalize_recovery` is its only full-access key, and OutLayer's keystore refuses every operation bound to that vault. You recover the per-vault master yourself by signing a `request_app_private_key` call to the MPC contract directly from the vault account.

## Why this exists

The per-vault master is derived deterministically by the NEAR MPC network from `(vault account, derivation_path)`. Anyone holding a full-access key on the vault can submit `request_app_private_key` (a full-access key can attach the 1 yoctoNEAR the MPC contract requires) and receive the same master OutLayer's keystore obtained through the vault's `request_master` proxy. This tool does that.

The only non-obvious input is `derivation_path` — `hex(HMAC-SHA256(default_master, "secret-path:vault-master:<vault_id>"))`, unguessable before the keystore's first derivation. That derivation is a transaction signed by the vault, so after it the path is public in its arguments and can be read from the vault's history.

## Build

```bash
cd scripts/customer-recovery
cargo build --release
```

Binary: `target/release/customer-recovery`.

## Run

> **Never paste your full-access private key on the command line.**
> CLI args end up in shell history and `ps` output. Pass it via the
> `VAULT_PRIVATE_KEY` env var instead.

```bash
export VAULT_PRIVATE_KEY="$(jq -r .private_key ~/.outlayer-recovery/vault.alice.testnet.json)"
export MPC_PUBLIC_KEY='bls12381g2:...'

./target/release/customer-recovery \
    --vault-id vault.alice.testnet \
    --from-chain \
    --rpc-url https://rpc.testnet.fastnear.com
unset VAULT_PRIVATE_KEY
```

Inputs:

| Flag | Source |
|---|---|
| `--vault-id` | Your vault sub-account |
| `--signer-private-key` / `VAULT_PRIVATE_KEY` | The private half of the key installed by `outlayer vault finalize-recovery <vault> <new_parent_pubkey>` — typically generated with `customer-recovery generate-key` before finalize |
| `--mpc-public-key` / `MPC_PUBLIC_KEY` | The MPC network's `bls12381g2:...` key for domain 2. Public, read it from the MPC contract: `near contract call-function as-read-only v1.signer public_key json-args '{"domain_id": 2}' network-config mainnet now` (testnet: `v1.signer-prod.testnet`) |
| `--derivation-path` OR `--from-chain` | Either pass the path, or let the tool find it on NEARblocks (below) |
| `--mpc-contract`, `--mpc-domain-id`, `--rpc-url`, `--nearblocks-url` | Defaults are testnet: `v1.signer-prod.testnet`, `2`, `https://rpc.testnet.fastnear.com`, `https://api-testnet.nearblocks.io`. Mainnet: `v1.signer`, `2`, a mainnet RPC, `https://api.nearblocks.io` |

URLs must be HTTPS (plain HTTP is accepted only for `localhost` / `127.0.0.1`).

The vault must hold enough NEAR to prepay the call's gas: 150 TGas plus 1 yoctoNEAR; unused gas is refunded.

## Output

```
# === Per-vault master recovered ===
# vault_id       = vault.alice.testnet
# derivation_path= a3f17c…

master_hex=4f8c…32 bytes hex…
```

This is the 32-byte master the keystore-worker used: the MPC response is decrypted with a fresh ephemeral BLS12-381 key, checked with a pairing against `MPC_PUBLIC_KEY`, and HKDF-SHA256-stretched exactly as the keystore does (`keystore-worker/src/mpc_ckd.rs`).

## End-to-end runbook

The full sovereign-exit procedure (initiate → wait → finalize → recover master → derive wallet → decrypt secrets) is [`docs/LEAVING_OUTLAYER.md`](../../docs/LEAVING_OUTLAYER.md).

[`walkthrough.sh`](./walkthrough.sh) runs the on-chain half plus master recovery for a vault that is **not yet unlocked**: it builds the binary, generates a key into `~/.outlayer-recovery/<vault_id>.json` (mode 0600), checks the logged-in `outlayer` account is the vault's parent, initiates unilateral recovery (or skips if one is running), sleeps until `finalize_after`, finalizes, confirms `unlocked == true` and recovers the master.

```bash
VAULT_ID=vault.alice.testnet \
MPC_PUBLIC_KEY='bls12381g2:...' \
NETWORK=testnet \
  ./walkthrough.sh
```

`NETWORK=mainnet` switches the MPC contract and NEARblocks host; `RPC_URL` overrides the RPC. The script refuses to overwrite an existing key file and always generates a new key, so once a finalize has landed, run the binary directly with the key you finalized with.

## Subcommands

All subcommands are local: none touches the network.

### `generate-key`

```bash
customer-recovery generate-key > new-parent.json
```

Emits a fresh ed25519 keypair as `{public_key, private_key}` JSON (the format `near-cli-rs` key files use) — the key to pass to `finalize_recovery`.

### `derive-wallet-key`

```bash
customer-recovery derive-wallet-key \
    --master <hex_64> \
    --wallet-id <uuid> \
    [--chain near|evm|solana|all]... [--sub-path <p>]... [--checks <n>]
```

`--master` may come from `CUSTOMER_RECOVERY_MASTER` instead. Re-derives the keys of a custody wallet from the master it was minted under — a vault's (`POST /register {"vault_id": "..."}`) or an exited owner's generation (`owner-exit claim`).

- `--chain` (repeatable): `near`; `evm`, or any EVM network name the keystore takes (`ethereum`, `base`, `hyperevm`, …) — one key for all of them; `solana` or `sol`; `all` for the three.
- `--sub-path <p>` (repeatable): an EVM sub-key. Refused unless it matches `[a-z0-9][a-z0-9._-]{0,63}`, the keystore's rule. A connector's path is `connector.<connector_id>.<label>`: Hyperliquid's `connector.hyperliquid.trading`, Polymarket's `connector.polymarket.trading`.
- `--checks <n>`: the NEAR keys of payment checks 0 … n−1, numbered in the order the wallet created them; a check's funds sit in `intents.near` under its account.

With any of these flags, the output is one entry per key — the wallet's own keys (near, evm, solana), then each sub-key in the order given, then the checks:

```json
{
  "wallet_id": "...",
  "keys": [
    { "chain": "near", "seed": "wallet:<id>:near", "address": "<hex>", "public_key": "ed25519:<base58>", "private_key": "ed25519:<base58>" },
    { "chain": "evm", "seed": "wallet:<id>:evm", "address": "0x<hex>", "public_key": "secp256k1:<hex>", "private_key": "0x<hex>" },
    { "chain": "solana", "seed": "wallet:<id>:solana", "address": "<base58>", "public_key": "<base58>", "private_key": "<base58>" },
    { "chain": "evm", "sub_path": "connector.hyperliquid.trading", "seed": "subkey:<id>:evm:connector.hyperliquid.trading", "address": "0x<hex>", "public_key": "secp256k1:<hex>", "private_key": "0x<hex>" },
    { "chain": "near", "check": 0, "seed": "wallet:<id>:near:check:0", "address": "<hex>", "public_key": "ed25519:<base58>", "private_key": "ed25519:<base58>" }
  ]
}
```

Without them, the NEAR key alone:

```json
{
  "wallet_id": "...",
  "near_address": "<hex>",
  "public_key": "ed25519:...",
  "private_key": "ed25519:..."
}
```

Private keys are in the form each chain's wallets import: NEAR `ed25519:<base58 of seed ‖ public key>` (near-cli); EVM `0x` + the 32-byte scalar (MetaMask and every EVM wallet); Solana base58 of the 64-byte `seed ‖ public key` keypair (Phantom, Solflare, Backpack; solana-cli's keypair file holds the same 64 bytes as a JSON array). Addresses and public keys are in the form `GET /wallet/v1/address` serves them, except NEAR's public key, which is `ed25519:<base58>` here and `ed25519:<hex>` there.

Each address MUST equal the one OutLayer gave you for that wallet — the NEAR one the `near_account_id` returned at registration. A mismatch means the recipe has diverged from the keystore — file a bug. `src/wallet_keys.rs` holds a vector the keystore's own test (`keystore-worker/src/api_tests.rs`, `recovery_tool_vector`) asserts too.

### `compute-wallet-id`

```bash
customer-recovery compute-wallet-id --account-id <acct> --seed <s> [--vault-id <vault>]
```

Prints the deterministic `wallet_id` the coordinator assigns to a wallet created by a signed claim (`PUT /wallet/v1/api-key`, `Bearer near:`):
`UUID(SHA-256("outlayer:deterministic-wallet-id:" + account_id + ":" + seed [+ "\0vault:" + vault_id])[..16])`.

### `decrypt-secret`

```bash
customer-recovery decrypt-secret \
    --master <hex_64> \
    --seed 'project:owner.near/project-name:owner.near' \
    --ciphertext-base64 'AQB...'
```

Decrypts an on-chain ciphertext (`get_secrets(accessor, profile, owner).encrypted_secrets` on the OutLayer contract) locally. Detects the format the same way the keystore does (`keystore-worker/src/crypto.rs::decrypt`):

| First byte | Format | Algorithm |
|---|---|---|
| `0x01` (and ≥ 61 bytes) | ECIES v1 — written by the CLI and the dashboard | X25519 ECDH with the recipient key `HMAC-SHA256(master, "ecies:" + seed)` + HKDF-SHA256(`outlayer-keystore-v1`) + ChaCha20-Poly1305 |
| otherwise | Older symmetric format | ChaCha20-Poly1305 keyed by the ed25519 verifying key of `HMAC-SHA256(master, seed)` |

Seed per accessor (matches the seeds the keystore builds in `keystore-worker/src/api.rs`):

| Accessor | Seed |
|---|---|
| `Project { project_id }` | `project:<project_id>:<owner>` |
| `Repo { repo, branch: Some(b) }` | `<normalized_repo>:<owner>:<b>` |
| `Repo { repo, branch: None }` | `<normalized_repo>:<owner>` |
| `WasmHash { hash }` | `wasm_hash:<hash>:<owner>` |

Plaintext is UTF-8 JSON (`{"KEY":"value", ...}`).

### Test helpers

`verify-sign-message`, `sign-nep413`, `sign-api-key-claim` and `sign-bearer-near` build or check the signatures the coordinator's NEP-413 and signed-claim auth expect. The e2e suites use them; their flags are documented on each subcommand in `src/main.rs`.

## Reproducing your wallet addresses

Every wallet key the keystore serves is `HMAC-SHA256(master, seed)[..32]` used as the key material, with these seeds (`keystore-worker/src/api.rs::wallet_seed`, `subkey_seed`; `keystore-worker/src/ephemeral_keys.rs`):

| Key | Seed | Key / address |
|---|---|---|
| NEAR | `wallet:{wallet_id}:near` | ed25519 seed; implicit account = hex(public key) |
| EVM (every EVM chain, one address) | `wallet:{wallet_id}:evm` | secp256k1 secret scalar; address = last 20 bytes of keccak256(uncompressed public key) |
| Solana | `wallet:{wallet_id}:solana` | ed25519 seed; address = base58(public key) |
| EVM sub-key | `subkey:{wallet_id}:evm:{sub_path}` | as EVM |
| Payment check `n` | `wallet:{wallet_id}:near:check:{n}` | as NEAR |

`derive-wallet-key` implements every row.

### Verification recipe

```python
# Verifies the recovered master matches the NEAR address OutLayer gave you.
# Requires: pip install pynacl
import hmac, hashlib
from nacl.signing import SigningKey

master = bytes.fromhex("d24457ae...your master_hex...")
wallet_id = "27487fc6-b67d-4a19-a1d7-db352c0475c5"
seed = f"wallet:{wallet_id}:near".encode()

secret = hmac.new(master, seed, hashlib.sha256).digest()[:32]
pubkey = bytes(SigningKey(secret).verify_key)
print(pubkey.hex())   # → the wallet's near_account_id
```

If this prints the `near_account_id` you saved for that `wallet_id`, the master is correct.

### Auto-discovery of `derivation_path`

`--from-chain` reads the vault's transactions from NEARblocks API v3, newest first (`GET <nearblocks-url>/v3/accounts/<vault>/txns?limit=25`, following the `meta.next_page` cursor for up to 20 pages), takes the newest one the vault signed that succeeded and calls `request_master` on the vault itself (its MPC proxy, which is how the keystore derives) or `request_app_private_key` on the MPC contract (`--mpc-contract`), and reads `request.derivation_path` from its arguments on the detail endpoint (`GET <nearblocks-url>/v3/txns/<hash>`). A failed call, or a method of that name on any other contract, is not used.

If it finds nothing, take the hash of any `request_master` transaction from the vault's history (any NEAR explorer) and read the path from an RPC node — an archival one if the transaction is old:

```bash
TX=<tx_hash>
curl -s -X POST https://rpc.testnet.fastnear.com -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":\"q\",\"method\":\"EXPERIMENTAL_tx_status\",
       \"params\":[\"$TX\",\"<your-vault-id>\"]}" | \
  jq -r '.result.transaction.actions[0].FunctionCall.args' | base64 -d | \
  jq -r '.request.derivation_path'
```

and pass it with `--derivation-path`.

If the vault has no such transaction at all, no keystore ever derived its master: no wallet or secret was ever served under it, and there is nothing to recover.

## Owner exit

An owner registered in the keystore DAO, with no vault, leaves with
`customer-recovery owner-exit` — the procedure is
[`docs/OWNER_EXIT.md`](../../docs/OWNER_EXIT.md).

| Command | Does |
|---|---|
| `owner-exit status --owner <account>` | the owner's record in the DAO: generation, exit window, approvers, a pending exit |
| `owner-exit initiate --owner <account>` | starts an exit; attaches the DAO's exit fee |
| `owner-exit cancel --owner <account>` | drops the pending action: an exit, or a change of the approvers |
| `owner-exit claim --owner <account> --claim-file <path>` | after the exit window: asks the DAO for the escrow key, opens the escrow, prints `master_hex=…` |
| `owner-exit open --claim-file <path>` | reads the claim's result from the chain by the transaction hash in the claim file, opens the escrow, prints `master_hex=…` |
| `owner-exit wallets --owner <account> --generation <n>` | the wallets at numbered seeds, with their NEAR accounts |

`--dao` (default `dao.outlayer.testnet`; mainnet `dao.outlayer.near`) and `--rpc-url`
(default a testnet RPC) go with every command that reads the chain; `open` takes its DAO
from the claim file and needs the RPC of that DAO's network. An RPC URL that carries an API key goes in
`RPC_URL` in the environment instead. The owner's full-access key is
`OWNER_PRIVATE_KEY`, MPC's key `MPC_PUBLIC_KEY`, the master for `wallets`
`CUSTOMER_RECOVERY_MASTER` — in the environment, not on the command line.

`claim` writes the claim file (mode 0600) before it sends the transaction: it holds the
one-time key MPC's answer is encrypted to and the hash of the claim transaction, whose
result on chain is that answer. A claim that returned the key is not made again; the claim file
is what opens it, through `open` — from any RPC for the first days, and from an archival
RPC after that, since an ordinary node drops a transaction's result. A claim refuses a path where a file
exists — it may hold the key of an earlier claim — so each claim takes a new path. When
`claim` ends without printing a master, run `open` on its file first: a transaction whose
answer to the sender was lost may have gone through.

The master is opened exactly as the keystore sealed it
(`keystore-worker/src/crypto.rs`, `seal_owner_escrow`); a test holds this tool to the
keystore's vector.

`sign-bearer-near --owner` builds a `Bearer near:` token for an owner's scope, and
`sign-api-key-claim` signs `api-key:<seed>:<timestamp>:<key_hash>[:<vault_id>]`.

## Caveats

- Run the tool on a host you trust — the master and derived private keys are printed to stdout. Redirect them to a 0600 file; don't pipe them into a logger or a shared terminal.
- `RUST_LOG=debug` prints verbose progress. Default is INFO.
