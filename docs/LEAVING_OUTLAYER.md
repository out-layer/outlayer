# Leaving OutLayer (Sovereign Exit)

This document is the **operational runbook** for taking a per-customer
vault out from under OutLayer's keystore and continuing to use the
same wallet addresses and the same on-chain secrets without OutLayer
infrastructure.

It targets two audiences:

1. **Customers** who have deployed a vault with `outlayer vault init`
   and want a procedure to follow if OutLayer becomes unavailable,
   untrustworthy, or simply unwanted.
2. **Operators / auditors** reviewing the sovereignty guarantee —
   each step points to the contract / keystore code that enforces it.

For the architecture and trust model of vaults, see
[`VAULTS.md`](../VAULTS.md) and https://app.outlayer.ai/docs/vaults.

---

## The promise, and its limits

After you run the procedure in this document:

| Capability | Before (OutLayer in the loop) | After (sovereign exit) |
|---|---|---|
| Sign transactions for your custody wallet(s) | OutLayer keystore signs via `/wallet/v1/*` | You sign locally with a re-derived key |
| Decrypt secrets bound to the vault | OutLayer worker / keystore decrypts in TEE | You decrypt locally with the recovered master |
| Mint new wallets / API keys, run code | Coordinator | Not available — you've left OutLayer |
| Control the vault account and its balance | TEE function-call key only | Your full-access key only |

The unilateral exit needs no cooperation from OutLayer: not its API,
not its dashboard, not its DAO. It needs your parent account, the NEAR
RPC, the NEAR MPC network, and the open-source tools in this repo and
in [outlayer-cli](https://github.com/out-layer/cli).

What the exit does **not** do:

- **It does not rotate any key.** The master you recover is the master
  the keystore used; every wallet keeps its address and its key. The
  exit ends OutLayer's ability to derive the master again, not any
  copy obtained before. While the vault was locked, a keystore build
  approved by OutLayer's DAO could obtain the master (see
  [VAULTS.md — What it does not guarantee at this stage](../VAULTS.md#what-it-does-not-guarantee-at-this-stage)).
  If you are leaving because you distrust a past keystore, move funds
  to fresh keys after Phase B and re-encrypt your secrets.
- **The wallet policy no longer applies.** Limits, allowlists and
  approvals were enforced by the keystore before it signed. A key you
  hold locally signs anything.

---

## What you need to keep before exit

Do this once when you deploy each vault and store the result offline:

1. **Vault id** — printed by `outlayer vault init`. Example:
   `vault.alice.near`.
2. **Parent NEAR account credentials** — the account in the vault's
   `parent` field. Only it can initiate a unilateral recovery and
   finalize any recovery. Treat it like a cold-storage wallet.
3. **`wallet_id`** (UUID) and **`near_account_id`** of every custody
   wallet minted under the vault. `POST /register {"vault_id": "..."}`
   returns them once; save the response. A wallet's NEAR key is
   `HMAC-SHA256(per_vault_master, "wallet:<wallet_id>:near")`, so
   without the UUID you cannot reach a specific wallet's key. Wallets
   created by a signed claim (`PUT /wallet/v1/api-key` or `Bearer
   near:` with a `vault_id`) have a deterministic id you can recompute
   offline with `customer-recovery compute-wallet-id --account-id
   <acct> --seed <seed> --vault-id <vault>`.
4. **Profile + accessor of every vault-bound secret** — needed to look
   up its ciphertext on chain after exit.
5. **(Optional) `MPC_PUBLIC_KEY`** — the `bls12381g2:...` key the
   recovery tool uses to verify that the master came from the MPC
   network. It is public; read it from the MPC contract (domain 2):

   ```bash
   near contract call-function as-read-only v1.signer public_key \
     json-args '{"domain_id": 2}' network-config mainnet now
   # testnet: v1.signer-prod.testnet ... network-config testnet
   ```

   Store the answer so the recovery needs no lookup later.

Everything above except the parent's private key is public
information.

---

## The procedure in short

```bash
# 0. Build the tool (once).
cd scripts/customer-recovery && cargo build --release && cd -
BIN=./scripts/customer-recovery/target/release/customer-recovery

# 1. Start the on-chain exit (parent signs; `outlayer login mainnet` as the parent first).
outlayer vault initiate-unilateral-recovery vault.alice.near

# 2. Wait until `finalize_after` (shown in ns by `outlayer vault status vault.alice.near`).

# 3. Generate the key that will own the vault, then hand the vault to it.
mkdir -m 700 -p ~/.outlayer-recovery
"$BIN" generate-key > ~/.outlayer-recovery/vault.alice.near.json
outlayer vault finalize-recovery vault.alice.near \
  "$(jq -r .public_key ~/.outlayer-recovery/vault.alice.near.json)"

# 4. Recover the per-vault master.
VAULT_PRIVATE_KEY=$(jq -r .private_key ~/.outlayer-recovery/vault.alice.near.json) \
MPC_PUBLIC_KEY='bls12381g2:...' \
  "$BIN" --vault-id vault.alice.near --from-chain \
    --rpc-url https://rpc.mainnet.fastnear.com \
    --mpc-contract v1.signer \
    --nearblocks-url https://api.nearblocks.io
# stdout ends with: master_hex=<64 hex chars>
```

The rest (re-deriving wallets, decrypting secrets) is local.

[`scripts/customer-recovery/walkthrough.sh`](../scripts/customer-recovery/walkthrough.sh)
runs steps 0–4 for a vault that is **not yet unlocked**: it checks
that the logged-in account is the parent, skips initiate if a recovery
is already running, sleeps until `finalize_after`, finalizes and
confirms `unlocked == true`. Run it as
`VAULT_ID=vault.alice.near NETWORK=mainnet MPC_PUBLIC_KEY=... ./walkthrough.sh`.
It always generates a new key file and refuses to overwrite an
existing one, so once a finalize has landed, run step 4 directly with
the key you finalized with.

---

## Step-by-step

### Phase A — On-chain exit (parent-signed)

#### A.1 Confirm the vault is yours and locked

```bash
outlayer vault status vault.alice.near
```

Required fields:
- `Parent: <your_account>` — must be the account whose key you hold.
  `unilateral_initiate_recovery` and `finalize_recovery` both require
  `env::predecessor_account_id() == self.parent`.
- `Status: locked (TEE-controlled)` — if it already says
  `UNLOCKED (recovered)`, skip to Phase B.
- `Recovery: none in progress` — if a recovery is running, see
  "What if someone front-ran me?" below.

If `Parent` is wrong, **stop**: every following call will be rejected.

#### A.2 Initiate unilateral recovery

```bash
outlayer vault initiate-unilateral-recovery vault.alice.near
```

The contract records `finalize_after = now + exit_window` and
`finalize_before = finalize_after + 7 days`. The exit window was set
at deploy (`--exit-window`, default `24h`; the production contract
accepts 1 day to 30 days). `outlayer vault set-exit-window` (parent
only, same range) changes it for FUTURE recoveries; a recovery in
flight keeps the timestamps it was initiated with.

#### A.3 Wait the exit window

Real time. Finalizing before `finalize_after` panics with `recovery
delay not yet elapsed` and changes nothing. You then have 7 days to
finalize; a finalize after `finalize_before` clears the recovery (the
vault stays locked) and you start again at A.2.

#### A.4 Generate the key that will own the vault

```bash
mkdir -m 700 -p ~/.outlayer-recovery
./scripts/customer-recovery/target/release/customer-recovery generate-key \
    > ~/.outlayer-recovery/vault.alice.near.json
chmod 600 ~/.outlayer-recovery/vault.alice.near.json
```

The output is `{public_key, private_key}` JSON in the format
`near-cli-rs` uses. This keypair becomes the **only** full-access key
on the vault. Back the file up offline immediately: losing it after
finalize means losing the vault.

#### A.5 Finalize — atomic key swap

```bash
NEW_PUBKEY=$(jq -r .public_key ~/.outlayer-recovery/vault.alice.near.json)
outlayer vault finalize-recovery vault.alice.near "$NEW_PUBKEY"
```

What happens on chain (`vault-contract/src/lib.rs`):

1. Parent-only check (`predecessor == self.parent`).
2. Window check (`finalize_after <= now <= finalize_before`).
3. One Promise batch on the vault account (`dispatch_swap`):
   `DeleteKey(initial_tee_key)`, `DeleteKey(k)` for every entry in
   `registered_tee_keys`, `AddFullAccessKey(new_pubkey)`.
4. `callback_after_swap` sets `unlocked = true` and clears `recovery`
   only if the batch succeeded. If it failed (e.g. the pubkey is
   already a key on the account), state is unchanged and you can
   retry with a fresh keypair inside the same window.

After this transaction OutLayer has **no access key on the vault
account**, and `request_master` refuses an unlocked vault, so the
per-vault master cannot be derived again by anyone but you. The
keystore checks `unlocked` on every operation that names the vault,
refuses, and evicts the master from memory. The coordinator answers
`/call/<owner>/<project>` requests whose Project secret is bound to
this vault with **HTTP 423 Locked** before dispatching any work.

#### A.6 Confirm the unlock landed

```bash
outlayer vault status vault.alice.near
# Status:          UNLOCKED (recovered)
# Recovery:        none in progress
```

`vault.get_state().unlocked == true` is the on-chain ground truth.

---

### Phase B — Local key derivation

From here you only need a NEAR RPC, the MPC contract and (for
auto-discovery) a NEARblocks-compatible indexer.

#### B.1 Recover the per-vault master via MPC CKD

```bash
export VAULT_PRIVATE_KEY=$(jq -r .private_key ~/.outlayer-recovery/vault.alice.near.json)
export MPC_PUBLIC_KEY='bls12381g2:...'   # from step 5 of "What you need to keep"

./scripts/customer-recovery/target/release/customer-recovery \
    --vault-id vault.alice.near \
    --from-chain \
    --rpc-url https://rpc.mainnet.fastnear.com \
    --mpc-contract v1.signer \
    --nearblocks-url https://api.nearblocks.io
unset VAULT_PRIVATE_KEY
```

The tool's defaults are testnet (`v1.signer-prod.testnet`,
`rpc.testnet.fastnear.com`, `api-testnet.nearblocks.io`); pass the
mainnet values as above. `--mpc-domain-id` defaults to `2`.

What `--from-chain` does: reads the vault's 20 most recent
transactions from NEARblocks, takes the newest one signed by the vault
that calls `request_master` (or `request_app_private_key`), and reads
`request.derivation_path` from its arguments. The path is
`hex(HMAC-SHA256(default_master, "secret-path:vault-master:<vault_id>"))`
— unguessable before the keystore's first derivation, public in that
transaction afterwards. If auto-discovery finds nothing (more than 20
newer transactions, or the indexer is unavailable), pass
`--derivation-path` yourself; see
[`scripts/customer-recovery/README.md`](../scripts/customer-recovery/README.md#auto-discovery-of-derivation_path).

The tool then signs `request_app_private_key` to the MPC contract
**from the vault** with your new key (150 TGas, 1 yoctoNEAR; the vault
must hold enough NEAR to prepay the gas), decrypts the response with a
fresh ephemeral BLS12-381 key, verifies it with a pairing check against
`MPC_PUBLIC_KEY`, and HKDF-stretches the 48-byte secret to the 32-byte
master. MPC binds the result to `(vault account, derivation_path)`, so
this is the same master the keystore obtained through `request_master`.

Output ends with:

```
master_hex=<64 hex chars>
```

**Save the master.** Anyone who has it can derive every wallet key and
decrypt every secret of the vault.

If the keystore never derived a master for this vault (no wallet or
secret was ever served), there is no past transaction and nothing
encrypted under it.

#### B.2 Re-derive each wallet's keys

For every NEAR wallet you minted under the vault:

```bash
./scripts/customer-recovery/target/release/customer-recovery derive-wallet-key \
    --master "$MASTER_HEX" \
    --wallet-id "<the UUID you saved at registration>"
```

Output is JSON:

```json
{
  "wallet_id": "...",
  "near_address": "<hex>",
  "public_key": "ed25519:...",
  "private_key": "ed25519:..."
}
```

`near_address` MUST equal the `near_account_id` the coordinator
returned at registration. If it differs, the derivation recipe and the
keystore have diverged — file a bug.

You can now sign any NEAR transaction as that wallet:

```bash
near tokens "<near_address>" send-near alice.near '0.01 NEAR' \
    network-config mainnet \
    sign-with-plaintext-private-key 'ed25519:...' send
```

Balances held for the wallet in other contracts (for example
`intents.near`) belong to the same account and move with transactions
signed by this key.

`derive-wallet-key` covers the NEAR key only. The wallet's other chain
keys use the same master with these seeds (keystore
`api.rs::wallet_seed`, `crypto.rs`); the tool has no subcommand for
them, so derive them with any HMAC-SHA256 implementation:

| Chain | Seed | Key |
|---|---|---|
| NEAR | `wallet:<wallet_id>:near` | ed25519 seed = HMAC output |
| EVM (all EVM chains, one address) | `wallet:<wallet_id>:evm` | secp256k1 secret scalar = HMAC output (big-endian) |
| Solana | `wallet:<wallet_id>:solana` | ed25519 seed = HMAC output |

#### B.3 Decrypt each on-chain secret

For every vault-bound secret (stored with `outlayer secrets set
--vault-id <vault>` or from the dashboard with vault scope):

```bash
# 1. Fetch the ciphertext from the contract.
ARGS=$(jq -cn --arg pid 'alice.near/my-project' --arg owner 'alice.near' --arg profile 'prod' \
    '{accessor: {Project: {project_id: $pid}}, profile: $profile, owner: $owner}')
ARGS_B64=$(printf '%s' "$ARGS" | base64 | tr -d '\n')
CIPHERTEXT=$(curl -s https://rpc.mainnet.fastnear.com -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"outlayer.near\",\"method_name\":\"get_secrets\",\"args_base64\":\"$ARGS_B64\"}}" \
    | jq -r '.result.result | implode' \
    | jq -r '.encrypted_secrets')

# 2. Decrypt with the recovered master and the accessor's seed.
./scripts/customer-recovery/target/release/customer-recovery decrypt-secret \
    --master "$MASTER_HEX" \
    --seed 'project:alice.near/my-project:alice.near' \
    --ciphertext-base64 "$CIPHERTEXT"
```

Output is the plaintext JSON object you stored (`{"KEY":"value", ...}`).
`get_secret_vault(accessor, profile, owner)` on the same contract
returns the vault a secret is bound to.

The seed is fixed per accessor (keystore `api.rs`):
- **Project** (`--project owner/name`): `project:<owner>/<name>:<owner>`
- **Repo**: `<normalized_repo>:<owner>:<branch>`, or
  `<normalized_repo>:<owner>` when the secret has no branch
- **WasmHash** (`--wasm-hash <sha256>`): `wasm_hash:<hash>:<owner>`

`decrypt-secret` detects the format: ECIES v1 (first byte `0x01`; what
the CLI and the dashboard write), otherwise the older symmetric
ChaCha20-Poly1305 format, which the keystore also still reads.

---

## What survives the exit

| Artifact | You have | OutLayer has |
|---|---|---|
| Vault account and its balance | the only full-access key | no key |
| Per-vault master (32 bytes) | recovered locally | no way to derive it again; an honest keystore has evicted it from memory |
| Wallet private keys | derivable from master + wallet_id | derivable only from the master |
| On-chain ciphertext of secrets | readable + decryptable | readable; decryptable only with the master |
| `parent` field on the vault | unchanged (your account) | — |

A copy of the master taken before the exit is not affected by it — see
"What the exit does not do" above.

---

## What you give up

- **OutLayer's keystore signing API** — `/wallet/v1/*` requests for
  wallets under this vault are refused: the keystore reports the vault
  as unlocked. You sign locally instead.
- **`/call/<owner>/<project>` with vault-bound secrets** — refused with
  HTTP 423. Execution that does not use vault-bound secrets is
  unaffected.
- **The dashboard** shows the vault as `UNLOCKED (recovered)`. Unlock
  is one-way: no method re-locks a vault.

You can deploy a **new** vault under the same parent at any time, on
another sub-account name (`outlayer vault init --name <other>`).

---

## What if someone front-ran me?

They can't take the vault.

`finalize_recovery` panics with `only the parent account can finalize
recovery` for any other caller, before reading or changing state. A
watcher who sees your `finalize_after` pass cannot substitute their
own key; you can finalize at any point until `finalize_before`.

`unilateral_initiate_recovery` is parent-only as well.

`initiate_recovery` (the cessation path) is permissionless, but
`callback_initiate` refuses unless the DAO has declared cessation. A
recovery someone else started while cessation is declared still ends
with **your** key, because only the parent can finalize it. A
cessation recovery that is in flight blocks a unilateral one (one
recovery at a time) until it is finalized or expires.

---

## Trade-off the design makes

If your **parent account becomes unavailable** (lost key, deceased
operator, lost multisig signers), the vault stays locked forever, even
after DAO cessation. The alternative — anyone can finalize — would let
a third party install their own key at finalize time.

For high-value deployments, give the parent account its own recovery
(multisig, social recovery) out-of-band.

---

## Verification check-list (for auditors)

The exit rests on five properties, each testable on its own:

1. **Parent-only `finalize_recovery`** — `require!(predecessor ==
   self.parent)` before any state change. Tests:
   `vault-contract/src/lib.rs` unit tests
   `finalize_recovery_rejects_non_parent_unilateral` /
   `_cessation`; sandbox test
   `vault-contract/tests/integration.rs::unilateral_finalize_rejects_non_parent_after_window`.
2. **Atomic key swap** — `dispatch_swap` issues `DeleteKey(*) +
   AddFullAccessKey(new_pubkey)` in one batch; state changes only in
   `callback_after_swap` on success. Tests:
   `callback_after_swap_commits_state_on_success`,
   `callback_after_swap_leaves_state_untouched_on_failure`.
3. **Keystore refuses unlocked vaults** —
   `keystore-worker/src/mpc_ckd.rs` `ensure_customer_loaded` →
   `assert_serving_allowed` reads `is_vault_verified` and
   `vault.get_state()` on every call, refuses on `unlocked == true`
   and evicts the cached master.
4. **No derivation after unlock** — `request_master` requires
   `!self.unlocked` and a self-call; the swap removed every TEE key.
5. **MPC CKD is deterministic** — the same `(predecessor, derivation_path)`
   yields the same secret, so `customer-recovery` reaches the master
   the keystore used.

The coordinator's `/call` pre-check
(`outlayer-coordinator/src/handlers/call.rs`,
`assert_secret_vault_serving_allowed`, private repo) is a fast-fail in
front of property 3, not a security boundary.

The whole procedure runs end-to-end on testnet in
[`tests/unified_vault_e2e.sh`](../tests/unified_vault_e2e.sh): V3
(finalize → keystore refuses → MPC recovery → offline re-derivation of
the wallet addresses), V5 (the same for a `wk_` wallet, ending with a
real transfer signed by the recovered key), V4 (secret decryption
after recovery).

---

## Files referenced from this document

| Path | Purpose |
|---|---|
| [`scripts/customer-recovery/`](../scripts/customer-recovery/) | Standalone MPC CKD + key derivation + secret decrypt tool |
| [`scripts/customer-recovery/walkthrough.sh`](../scripts/customer-recovery/walkthrough.sh) | Interactive runbook for Phase A + B.1 |
| [`scripts/customer-recovery/README.md`](../scripts/customer-recovery/README.md) | CLI reference for the tool |
| [`tests/unified_vault_e2e.sh`](../tests/unified_vault_e2e.sh) | End-to-end test of the exit on testnet |
| [`vault-contract/src/lib.rs`](../vault-contract/src/lib.rs) | Contract source — `finalize_recovery`, `dispatch_swap`, `callback_after_swap` |
| [`VAULTS.md`](../VAULTS.md) | Architecture and trust model |
