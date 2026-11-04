# Keystore Worker

The keystore is the OutLayer service that holds master secrets and derives every key
from them: the keys that encrypt and decrypt user secrets, custody-wallet signing keys,
per-project storage keys, VRF keys, and the keys a WebAssembly artefact declares. It runs
as a dstack confidential VM on Intel TDX hosts operated by OutLayer.

Callers:

- **TEE workers** — decrypt a job's secrets and receive its declared keys, encrypt and
  decrypt storage, VRF.
- **The coordinator** — relays the dashboard's secret-store calls and every custody-wallet
  operation (derive an address, check a policy, sign).
- **Anyone** — `/health`, `/pubkey` (default master), `/vrf/pubkey`.

## Where the master comes from

In production (`TEE_MODE=outlayer_tee`, `USE_TEE_REGISTRATION=true`):

1. At boot the keystore generates a registration keypair (`KEYSTORE_KEY_TYPE`, ed25519 or
   ml-dsa-65) in enclave memory. It is never written to disk.
2. It reads its TDX measurements from a fresh quote and asks the DAO contract
   (`KEYSTORE_DAO_CONTRACT`) whether they are approved. If not, it submits nothing and stops.
3. The init account (`INIT_ACCOUNT_ID`) submits `submit_keystore_registration` with the
   quote; the contract verifies it and opens a proposal.
4. The keystore polls for approval for up to 30 minutes. A DAO vote installs its key as a
   function-call key on the DAO account.
5. With that key it calls the DAO's `request_key`, which forwards a confidential key
   derivation (CKD) request to the NEAR MPC contract. The response is encrypted to a
   one-shot BLS12-381 key generated in enclave memory; the keystore decrypts it, verifies
   it against `MPC_PUBLIC_KEY`, and stretches it with HKDF to the 32-byte default master.
   Every approved keystore receives the same master, so a restarted or upgraded keystore
   reads every secret stored before.
6. Only then does it bind its HTTP port. An instance that fails any step stays up without
   a listener, so the gateway never routes traffic to it.

Per-customer vault masters are derived on first use: the keystore signs
`request_master` on the customer's own vault contract with a key derived for that vault,
and the vault forwards the CKD request to MPC. The derivation path is an HMAC of the
default master, so nobody outside an approved keystore can request the same master
first. Vault masters live in memory and are evicted when the vault leaves enclave control.

The contract side, and what the DAO owner and the DAO account's full-access key can do at
this stage, is in [keystore-dao-contract/README.md](../keystore-dao-contract/README.md).

Outside a TEE (`TEE_MODE=none`, `USE_TEE_REGISTRATION=false`) the master is
`KEYSTORE_MASTER_SECRET`, or a random one generated at start and printed once to stderr
(or to the file named by `KEYSTORE_MASTER_SECRET_OUT_PATH_NON_TEE`). In TEE mode either of
those variables aborts startup, and `TEE_MODE=outlayer_tee` without
`USE_TEE_REGISTRATION=true` aborts too.

## How a worker authenticates

A request to a worker route needs both:

1. `Authorization: Bearer <token>` whose SHA-256 is in `ALLOWED_WORKER_TOKEN_HASHES`;
2. `X-TEE-Session: <uuid>` naming a live session, when `TEE_MODE=outlayer_tee`.

A session comes from a challenge-response:

```
POST /tee-challenge                      → {"challenge": "<64 hex>"}     (valid 60 s, one use)
POST /register-tee {public_key, challenge, signature}
     → signature verified (schemes allowed by TEE_ALLOWED_KEY_TYPES)
     → view_access_key(OPERATOR_ACCOUNT_ID, public_key) must exist on chain
     → {"session_id": "<uuid>"}
```

`OPERATOR_ACCOUNT_ID` is the worker registration contract (`worker.outlayer.near`), which
adds a worker's key only after verifying its TDX quote; see
[WORKER_ATTESTATION.md](../WORKER_ATTESTATION.md).

What the check does and does not cover:

- It accepts **any** access key on the operator account, of any permission. A full-access
  key on `worker.outlayer.near`, if one is present, opens a session as well as a
  TDX-registered key does.
- The key is checked once, at `/register-tee`. Sessions live in memory until the keystore
  restarts; they do not expire, and removing the key from the operator account does not
  end a session already open.
- With `TEE_MODE=none` no session is required: the bearer token alone reaches the worker
  routes.

A restarted keystore has no sessions; a worker that receives "TEE session not found"
re-registers and retries.

## API

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | `{"status": "ok", "tee_mode": "outlayer_tee" \| "none"}` |
| `POST /pubkey` | none; coordinator or worker token when `vault_id` is set | public key to encrypt a secret to |
| `GET /vrf/pubkey` | none | VRF public key |
| `POST /decrypt`, `/encrypt`, `/decrypt-raw`, `/storage/encrypt`, `/storage/decrypt`, `/vrf/generate` | worker token + TEE session | job secrets and declared keys; storage; VRF |
| `POST /add_generated_secret`, `/update_user_secrets` | coordinator token | secrets generated inside the keystore; secret updates |
| `POST /wallet/*` (derive-address, sign, evm/*, solana/*, sign-policy, sign-secret-store, sign-secret-delete, check-policy, encrypt-policy, decrypt-policy, derive-ephemeral-key) | coordinator token | custody wallets |
| `POST /sign-vault-verification` | coordinator token | verifies a vault and submits `mark_vault_verified` on the DAO |
| `POST /derive-vault-tee-key` | coordinator or worker token | public key a vault must carry for the keystore |
| `POST /tee-challenge`, `/register-tee` | coordinator or worker token | TEE session |
| `GET /admin/loaded-vaults` | coordinator or worker token | vault masters currently in memory |
| `POST /admin/evict-customer`, `/admin/ban-vault` | worker token | drop a vault master; ban a vault on the DAO |

With TEE registration the port opens only once the master is loaded. Errors are
`{"error": "<message>"}`.

### `POST /pubkey`

```json
{"seed": "github.com/alice/app:alice.near", "secrets_json": "{\"API_KEY\":\"...\"}", "vault_id": null}
```

Returns `{"pubkey": "<hex>"}`, the X25519 public key of
`HMAC-SHA256(master, "ecies:" || seed)`. Before deriving, the keystore parses
`secrets_json` and refuses reserved names and the `PROTECTED_` prefix, which marks secrets
generated inside the keystore. `secrets_json` carries the plaintext secrets: the dashboard
sends it through the coordinator's `/secrets/pubkey`, so the coordinator relays them in the
clear on the way to this check. The ciphertext the client then stores on the contract is
ECIES: X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305,
`[0x01 | ephemeral_pubkey(32) | nonce(12) | ciphertext | tag(16)]`.

### `POST /decrypt`

```json
{
  "accessor": {"type": "Repo", "repo": "github.com/alice/app", "branch": null},
  "profile": "default",
  "owner": "alice.near",
  "user_account_id": "bob.near",
  "task_id": "123",
  "executed_wasm_sha256": "<64 hex>",
  "predecessor_id": "bob.near"
}
```

`accessor.type` is `Repo`, `WasmHash`, `Project` or `System`. The keystore reads the
encrypted row from the contract (`NEAR_CONTRACT_ID`), evaluates its access condition
(`AllowAll`, `Whitelist`, `AccountPattern`, `NearBalance`, `FtBalance`, `NftOwned`,
`DaoMember`, `ValidUntil`, `WasmHash`, `Predecessor`, `Logic`, `Not`) and returns
`{"plaintext_secrets": "<base64>"}`. `user_account_id`, `predecessor_id` and
`executed_wasm_sha256` are taken from the worker on the trust of its session; balances,
membership and ownership are read from the chain. A body that names `signing_keys`,
`encryption_keys` or `task_key` is a keyed request, described under "Signing keys" below.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `SERVER_HOST`, `SERVER_PORT` | no (`0.0.0.0`, `8081`) | listen address |
| `NEAR_NETWORK` | no (`testnet`) | |
| `NEAR_RPC_URL` | yes | keyed RPC; every chain read and the registration transactions |
| `OFFCHAINVM_CONTRACT_ID` | yes | the OutLayer contract (`outlayer.near`) |
| `NEAR_CONTRACT_ID` | yes, to read secrets | the contract secrets are read from (`outlayer.near`) |
| `ALLOWED_WORKER_TOKEN_HASHES` | yes | comma-separated SHA-256 hex of worker tokens |
| `ALLOWED_COORDINATOR_TOKEN_HASHES` | yes | comma-separated SHA-256 hex of coordinator tokens |
| `TEE_MODE` | no (`none`) | `outlayer_tee` or `none` |
| `USE_TEE_REGISTRATION` | no (`false`) | `true`: master from MPC after the DAO vote |
| `OPERATOR_ACCOUNT_ID` | with `outlayer_tee` | account whose access keys admit a worker (`worker.outlayer.near`) |
| `TEE_ALLOWED_KEY_TYPES` | no (`ed25519`) | worker key schemes accepted for sessions, e.g. `ed25519,ml-dsa-65` |
| `KEYSTORE_KEY_TYPE` | no (`ed25519`) | registration key scheme: `ed25519` or `ml-dsa-65` |
| `KEYSTORE_DAO_CONTRACT` | with TEE registration | `dao.outlayer.near` |
| `INIT_ACCOUNT_ID`, `INIT_ACCOUNT_PRIVATE_KEY` | with TEE registration | pays for `submit_keystore_registration` (`init-keystore.outlayer.near`) |
| `MPC_CONTRACT_ID` | with TEE registration | `v1.signer` (mainnet), `v1.signer-prod.testnet` |
| `MPC_DOMAIN_ID` | with TEE registration | BLS12-381 domain, `2` |
| `MPC_PUBLIC_KEY` | with TEE registration | the domain's `bls12381g2:` public key; CKD responses are verified against it |
| `DSTACK_SIMULATOR_ENDPOINT` | no | dstack socket for quotes, `/var/run/dstack.sock` in the CVM |
| `KEYSTORE_MASTER_SECRET` | non-TEE only | 64-hex master |
| `KEYSTORE_MASTER_SECRET_OUT_PATH_NON_TEE` | non-TEE only | file a generated master is written to (mode 0600) |
| `KEYSTORE_ALLOW_INLINE_POLICY` | no | testing only: lets `/wallet/check-policy` take an inline encrypted policy instead of reading it from the chain |
| `LOG_MASTER_KEY_HASH` | no | `true` logs a SHA-256 of the master and extra registration diagnostics |
| `RUST_LOG` | no | log filter |

A token is generated and hashed like this; the worker or coordinator holds the token,
the keystore only its hash:

```bash
TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1
```

## Running

Locally, without a TEE:

```bash
cd keystore-worker
cp .env.example .env     # TEE_MODE=none, USE_TEE_REGISTRATION=false; set the token hashes
echo 'OFFCHAINVM_CONTRACT_ID=outlayer.testnet' >> .env   # required, absent from the example
cargo run --release
curl http://localhost:8081/health
```

`scripts/run_keystore.sh [dev|testnet|mainnet]` runs it with `.env.dev`, `.env.testnet`
or `.env`.

In production the keystore runs as a dstack CVM built from a pinned, attested release
image (`deploy/self-hosted-tdx/40-deploy-keystore.sh`). From an operator machine,
`scripts/deploy_tdx.sh keystore <testnet|mainnet> --version <ver> --node <host>` deploys
it, reads the new measurements, approves them on the DAO as the owner, waits for the
registration proposal and votes on it (printed for manual signing on mainnet), then polls
`/health`.

## Deploying

**Keystore first, then the workers for it.** A worker has its keystore instances baked in
(`KEYSTORE_BASE_URLS`, all of one version), so it only ever talks to keystores it was deployed
for — the new worker needs those keystores to already exist. The same pinning is why the two can
change their shared request shape in a single release with no deprecation window: a worker never
meets a keystore of a different version. With several instances listed the worker holds a TEE
session on the one serving it and moves to the next only when that one becomes unreachable.

Restarting the keystore mints a fresh registration key and needs a DAO vote within 30
minutes, so schedule the release when a voter is on hand. Retire the previous version's
keys afterwards with `scripts/revoke_old_keystore_keys.sh <network>`: it asks each TDX node
for the registration keys of its running keystores (`worker-ctl.sh keystore-keys <net>`),
keeps those, and proposes revoking every other approved key and removing every older
approved image.

## Keys

### Adding a key family

Every key this keystore holds is `HMAC-SHA256(master, seed)` over a seed
STRING, and the two curves — ed25519 (`derive_keypair`) and secp256k1
(`derive_secp256k1_keypair`) — feed the seed into the HMAC without a curve tag.
So two seeds that are the same string are the same key, whatever curve or
endpoint asked for it. The seed namespace is flat, and what keeps families of
keys apart is only the shape of their strings. Three consequences for anyone
adding a family:

1. **Know which endpoints hand out private material.** Two do:
   `/wallet/derive-ephemeral-key` (payment checks) and `/decrypt` when it names
   `signing_keys`, `encryption_keys` or `task_key` (key material, to a TEE
   worker). The exporter builds `wallet:{id}:{chain}:{sub_path}` from two
   request strings and returns the private key. Any signing key whose seed that
   endpoint could spell is a signing key it can export. The families it cannot
   reach are: two-segment seeds under `wallet:` (it always appends a non-empty
   third segment), and anything under a different root. `/decrypt` builds its
   strings itself, from validated fields, only under `signing-key:v1:`,
   `encryption-key:v1:` and `task-key:v1:` — see "Signing keys" below,
   `src/encryption_keys.rs` and `src/task_keys.rs`.

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

`no_exportable_seed_can_name_a_signing_key` in `api_tests.rs` encodes the invariant:
add the new family's seed to that test before adding the family.

### Signing keys

A WebAssembly artefact may declare signing keys in its manifest
(`signing_keys`); the guest signs with them through the `outlayer:signing-keys`
host interface, never seeing the seed.

```text
bind "project": HMAC-SHA256(master, "signing-key:v1:{type}:project:{project_uuid}:{caller}:{account_id}:{path}")
bind "wasm":    HMAC-SHA256(master, "signing-key:v1:{type}:wasm:{wasm_sha256}:{caller}:{account_id}:{path}")
```

No other binding exists; any other `bind` value is refused.

- `type` is `ed25519` or `secp256k1` — the keystore returns the 32-byte HMAC
  output for either, and the worker reads it as an ed25519 seed or a
  secp256k1 secret scalar; `path` is `[a-z0-9][a-z0-9_-]{0,31}`; `project_uuid` is
  the contract's `p{16 hex}` for the project, read through `get_project` on
  every run and never cached (a project deleted and created again under the
  same name is another uuid, and so other keys); `caller` is `signer` or
  `predecessor`; `account_id` is the job's `user_account_id` for a `signer`
  key and its `predecessor_id` for a `predecessor` key; `wasm_sha256` 64
  lowercase hex. No field can hold a `:`, so the string parses back uniquely.
  The keystore builds it (`src/signing_keys.rs`); a request never supplies one,
  and the project's `owner/name` id is not part of it. At most 3 signing keys
  per request.
- **Issued strictly by how the code is run.** A request that names a
  `project_id` is a project run and holds `project` keys only; one that names
  none is a direct run of a wasm URL and holds `wasm` keys only. There is no
  field saying how the run was started. A run built from GitHub is refused
  through a project by the contract's version (below), and directly by the
  worker, which holds the resolved code source; the keystore sees only the
  hash. A `predecessor` key on a request with no `predecessor_id`, or a
  caller that is the worker's placeholder for a missing account
  (`anonymous`), is refused. One key that does not match refuses the whole
  request.
- **Trusted, not verified:** `user_account_id`, `predecessor_id`,
  `executed_wasm_sha256` and `project_id` come from the worker on the trust of
  its TEE session, exactly as for secrets. Verified on chain: the project's
  version and owner, the vault's ownership.
- **One request per run.** A `/decrypt` body with a `signing_keys` or
  `encryption_keys` member (other than `null` or `[]`), or a `task_key` member
  (other than `null` or `false`), is a `KeyedDecryptRequest`: the job's secret
  row if it has one (`accessor` + `profile` + `owner`, all or none), plus
  `signing_keys: [{path, type, bind?, caller?, vault?}]`, `encryption_keys`,
  `task_key`, `project_id`, `executed_wasm_sha256`, `user_account_id`,
  `predecessor_id`. Every other body is a plain `DecryptRequest`; an object
  naming one of those members twice is neither and is refused (422) before
  either parser reads it. The answer is an object with independent parts:
  `{"secrets": {"status": "decrypted", "plaintext_secrets": …} | {"status": "not_found", "error": …}, "signing_keys": {path: seed_hex}, "encryption_keys": {path: key_hex}, "task_key": …}`
  (each part only when the request asked for it).
- **Independent checks.** The keys are judged first and in full; any refusal
  fails the whole request with `{"error": …, "code": "signing_keys_refused"}`
  before the row is read. The row is then judged by its own access condition,
  exactly as without keys: a row that does not exist (`ApiError::SecretsNotFound`,
  a 400 on a plain request) is reported as `secrets.status = "not_found"`
  beside the keys; any other refusal of the row fails the request with the
  status and message a plain request gets.
- A project run must run a `WasmUrl` version of its project:
  `get_version(project_id, executed_wasm_sha256)` on the contract must answer
  with a `WasmUrl` source of that hash, and `get_project(project_id)` must
  exist, be owned by the id's owner and carry a well-formed `uuid`; both are
  read together, at one final block, on every project run — two answers from
  different blocks are reconciled at the older one. A GitHub-sourced version is keyed by
  `repo@commit` and is refused. A direct run's `wasm` keys come from the hash
  the worker reports. Text from the RPC or the contract reaches a refusal or a
  log line cut to 200 characters.
- `vault` (on `project` keys only) selects that vault's master. The vault must
  be a direct sub-account of the project's owner — decided on the names, before
  the vault is read, so a vault that is not the owner's costs no RPC — AND name
  that owner as its `parent`; it is then loaded through the usual gate. What
  the chain or the gate says about the vault refuses with the code: another
  parent, not verified on keystore-dao or banned, unlocked — 403; underfunded —
  402. A chain that could not be asked or a master that could not be loaded is
  a 500 without the code, the keystore's own outage; a master that leaves
  memory between the checks and the derivation is a 503 without the code — a
  retry loads it again. Either way the default master is never used
  in its place. A `wasm` key cannot name a vault.
- `signing_key_seed_audit` in `api_tests.rs` pins the root against every other
  family, for both string shapes. A caller-written seed — a raw seed sent to
  `/pubkey`, `/encrypt` or `/add_generated_secret`, or a `Repo` secret
  accessor's `{repo}:{owner}[:{branch}]`, whose repository and branch are free
  strings on chain — that starts with `signing-key:`, `encryption-key:` or
  `task-key:` is refused with a 400; a repository URL never starts there. Were
  one derived, it would reach the master only as `ecies:` + seed, or bare for
  its public key alone.

## Troubleshooting

### Startup stops at "TEE measurements not approved"

The build's five measurements are not on the DAO's approved list; no transaction was sent.
The log prints the `add_approved_measurements` call to sign as the DAO owner. Approve, then
restart the keystore. `scripts/deploy_tdx.sh keystore` does this as part of a deploy.

### Startup stops waiting for the DAO vote

The registration proposal was not approved within 30 minutes. The instance stays up without
a listener. Restart it after a voter is available: the restart generates a new key and a new
proposal.

### "TEE session not found or expired"

The keystore has no session for this worker: it restarted, or the worker never completed the
handshake. The worker re-registers on this error for `/decrypt`, `/encrypt` and
`/decrypt-raw`; if that fails, check that the worker's key is still an access key on
`OPERATOR_ACCOUNT_ID`.

### "Invalid worker token"

The worker's `KEYSTORE_AUTH_TOKEN` hashes to nothing in `ALLOWED_WORKER_TOKEN_HASHES`.

## Development

```bash
cargo test
RUST_LOG=debug cargo run
```

## License

Apache-2.0.
