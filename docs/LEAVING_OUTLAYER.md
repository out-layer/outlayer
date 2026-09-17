# Leaving OutLayer (Sovereign Exit)

This document is the **operational runbook** for taking a per-customer
vault out from under OutLayer's keystore and continuing to use the
same wallet addresses and the same on-chain secrets without OutLayer
infrastructure.

It targets two audiences:

1. **Customers** who have deployed an MPC vault via `outlayer vault
   init` and want a step-by-step procedure to walk through if OutLayer
   becomes unavailable, untrustworthy, or simply unwanted.
2. **Operators / auditors** reviewing the sovereignty guarantee —
   each step has a "why this works" pointer to the contract / keystore
   code that enforces the property.

For the architectural rationale of MPC vaults (why they exist, what
guarantees the design provides), see
[`dashboard/app/docs/vaults/page.tsx`](../dashboard/app/docs/vaults/page.tsx)
(rendered at https://app.outlayer.ai/docs/vaults).

---

## The promise

After you run the procedure in this document:

| Capability | Before (OutLayer in the loop) | After (sovereign exit) |
|---|---|---|
| Sign transactions for your custody wallet(s) | OutLayer keystore signs via `/wallet/v1/*` | You sign locally with a re-derived ed25519 key |
| Decrypt secrets bound to the vault | OutLayer worker / keystore decrypts in TEE | You decrypt locally with the recovered master |
| Mint new wallets / mint API keys | Coordinator | Not available — you've left OutLayer |
| Recover funds locked on chain | N/A | Direct on-chain control via the parent / new-parent key |

You do **not** lose any value the vault held. You do **not** need
OutLayer's cooperation, web UI, or testnet/mainnet API to be online.

---

## What you need to keep before exit

Even on the happy path (OutLayer is online), do these once when you
deploy each vault and stash the result offline:

1. **Vault id** — printed by `outlayer vault init`. Example:
   `vault.alice.near`.
2. **Parent NEAR account credentials** — the account that the
   `parent:` field on the vault points to. Without this you cannot
   trigger `finalize_recovery`. Treat it like a cold-storage wallet.
3. **`wallet_id`** (UUID) and **`near_account_id`** for every
   custody wallet minted under the vault — both are returned by
   `POST /register {"vault_id": "..."}` once and never re-fetchable.
   The wallet's private key is **derived** from
   `HMAC-SHA256(per_vault_master, "wallet:<wallet_id>:near")`, so
   without the UUID you cannot reach a specific wallet's key.
4. **(Optional) `MPC_PUBLIC_KEY`** — the `bls12381g2:...` MPC
   verification key, used to check that the master secret really
   came from the MPC network. It is public and you read it off the
   chain yourself, from the signer contract and domain your vault's
   master was derived under:

   ```bash
   near contract call-function as-read-only v1.signer public_key \
     json-args '{"domain_id": 2}' network-config mainnet now
   ```

   Pre-stash the answer so the recovery script needs no network at
   all — nothing about it depends on OutLayer still being reachable.
5. **Profile + project_id of every vault-bound secret you store** —
   needed to look up the encrypted ciphertext on chain after exit.

All of the above is public information except the parent's private
key. Storing a list in a password manager next to that key is
sufficient.

---

## The procedure in 60 seconds

If you are reading this in an emergency and want the headline:

```bash
# 1. Trigger the on-chain exit (parent signs).
outlayer vault initiate-unilateral-recovery vault.alice.near
sleep $(( $(outlayer vault status vault.alice.near | grep -oE 'Exit window:.*[0-9]+s' | grep -oE '[0-9]+') + 10 ))

# 2. Generate a fresh key that you will own (offline).
./scripts/customer-recovery/target/release/customer-recovery generate-key \
    > ~/.outlayer-recovery/vault.alice.near.json
NEW_PUBKEY=$(jq -r .public_key ~/.outlayer-recovery/vault.alice.near.json)

# 3. Hand the vault to that key (atomic on-chain key-swap).
outlayer vault finalize-recovery vault.alice.near "$NEW_PUBKEY"

# 4. Recover the per-vault master.
VAULT_PRIVATE_KEY=$(jq -r .private_key ~/.outlayer-recovery/vault.alice.near.json) \
MPC_PUBLIC_KEY='bls12381g2:...' \
  ./scripts/customer-recovery/target/release/customer-recovery \
    --vault-id vault.alice.near \
    --from-chain \
    --rpc-url https://rpc.mainnet.fastnear.com \
    --mpc-contract v1.signer \
    --nearblocks-url https://api.nearblocks.io
# stdout includes: master_hex=<32 hex bytes>
```

That's the on-chain half. The rest (re-deriving wallets, decrypting
secrets) is local and doesn't touch the network. The walkthrough
script [`scripts/customer-recovery/walkthrough.sh`](../scripts/customer-recovery/walkthrough.sh)
runs all of steps 1-4 with idempotency, pre-flight checks, and
exit-window introspection — recommended over the inline form above.

---

## Step-by-step

### Phase A — On-chain exit (parent-signed)

#### A.1 Confirm the vault is yours and locked

```bash
outlayer vault status vault.alice.near
```

Required fields:
- `Parent: <your_account>` — must equal the NEAR account whose
  key you hold. The contract checks
  `env::predecessor_account_id() == self.parent` as the very first
  action of `finalize_recovery`; if you are not parent, this entire
  procedure is for a different person.
- `Status: locked (TEE-controlled)` — if it already says
  `UNLOCKED (recovered)`, skip to Phase B.
- `Recovery: none in progress` — if a recovery is already running
  and it was started by someone else, see "What if someone front-ran
  me?" below.

If `Parent` is wrong, **stop**. You will burn the gas of every
following call and the contract will reject them.

#### A.2 Initiate unilateral recovery

```bash
outlayer vault initiate-unilateral-recovery vault.alice.near
```

The contract records `finalize_after = now + exit_window`. The
exit window was chosen at deploy (`--exit-window 24h` by default,
configurable 60s–30d). Read the current value with `outlayer vault
status`. Setting a shorter window for testing is parent-only via
`outlayer vault set-exit-window` and only affects FUTURE recoveries
(an in-flight one freezes its timestamps at initiate time).

#### A.3 Wait the exit window

Real time. The contract enforces
`block_timestamp >= finalize_after` at finalize time. No way to
shortcut it on chain. Trying to finalize early panics with `recovery
delay not yet elapsed` (clean panic, no state mutation, you can
retry later within `finalize_before`).

#### A.4 Generate the key that will own the vault

```bash
mkdir -m 700 -p ~/.outlayer-recovery
./scripts/customer-recovery/target/release/customer-recovery generate-key \
    > ~/.outlayer-recovery/vault.alice.near.json
chmod 600 ~/.outlayer-recovery/vault.alice.near.json
```

The output is a `{public_key, private_key}` JSON in the format
`near-cli-rs` produces. This new keypair becomes the **only**
FullAccess key on the vault after finalize. Back this file up
offline immediately. Losing it after finalize = losing the vault.

#### A.5 Finalize — atomic key swap

```bash
NEW_PUBKEY=$(jq -r .public_key ~/.outlayer-recovery/vault.alice.near.json)
outlayer vault finalize-recovery vault.alice.near "$NEW_PUBKEY"
```

What this does on chain:

1. Parent-only check fires (`predecessor == self.parent`).
2. Exit window check fires
   (`now >= finalize_after && now <= finalize_before`).
3. The contract dispatches an atomic Promise batch:
   - `Promise::delete_key(initial_tee_key)` — removes the TEE
     function-call key OutLayer installed at deploy time.
   - `Promise::delete_key(k)` for every entry in
     `registered_tee_keys` (DAO-rotated TEE keys, if any).
   - `Promise::add_full_access_key(new_parent_pubkey)` — adds your
     new key.
4. `callback_after_swap` sets `unlocked = true` and clears
   `self.recovery` if and only if the swap receipt succeeded. If
   the swap panicked (e.g. the new pubkey collides with an existing
   key), state is unchanged — you can retry within the same
   `finalize_before` window with a fresh keypair.

After this transaction lands, **OutLayer no longer has any access
key on the vault account**. Their keystore can still hold a stale
per-vault master in memory until the indexer-driven eviction fires
(seconds), but they cannot derive a fresh one because the function
call key that authorised `vault.request_master(...)` is gone.

Independently, the coordinator now refuses any
`/call/<owner>/<project>` request that touches a secret bound to
this vault with **HTTP 423 Locked** — the vault-serving pre-check
fast-fails at the API boundary instead of letting the request
spend gas trying to decrypt.

#### A.6 Confirm the unlock landed

```bash
outlayer vault status vault.alice.near
# Status: UNLOCKED (recovered)
# Recovery: none in progress
```

`vault.get_state().unlocked == true` is the on-chain ground truth
that everything downstream (keystore eviction, coordinator
fast-fail, your own decrypt) keys off.

---

### Phase B — Local key derivation (offline)

You are no longer touching OutLayer. The remaining steps only need
the NEAR RPC and the MPC contract — both are operator-independent
NEAR infrastructure.

#### B.1 Recover the per-vault master via MPC CKD

```bash
export VAULT_PRIVATE_KEY=$(jq -r .private_key ~/.outlayer-recovery/vault.alice.near.json)
export MPC_PUBLIC_KEY='bls12381g2:...'  # ask ops; same value keystore-worker uses

./scripts/customer-recovery/target/release/customer-recovery \
    --vault-id vault.alice.near \
    --from-chain \
    --rpc-url https://rpc.mainnet.fastnear.com \
    --mpc-contract v1.signer \
    --nearblocks-url https://api.nearblocks.io
```

What `--from-chain` does: queries NEARblocks for the most recent
successful `request_app_private_key` tx originating from this vault,
extracts the `derivation_path` from its args, and re-uses it. The
path is `HMAC-SHA256(default_master, "vault-master:<vault_id>")` —
an opaque 32-byte value that was unguessable before the keystore's
first CKD call but appears in plaintext on chain after that call.

The binary submits its own `request_app_private_key(...)` to the
MPC contract, decrypts the encrypted G1 element with a fresh
ephemeral key, verifies via a pairing check, and HKDF-stretches
the 48-byte secret to a 32-byte master.

Output ends with:

```
master_hex=<64 hex chars>
```

**Save the master**. This is *the* secret. Anyone who has it can
derive every wallet, sign for the vault's secrets, etc.

#### B.2 Re-derive each wallet's NEAR keypair

For every wallet you minted under the vault (one per
`POST /register {"vault_id": "..."}`):

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
returned at `/register` time. If they differ, the derivation seed
shape diverged — file a bug.

You can now sign **any** NEAR transaction as that wallet directly:

```bash
near tokens "<wallet_address>" send-near alice.near '0.01 NEAR' \
    network-config mainnet \
    sign-with-plaintext-private-key 'ed25519:...' send
```

No OutLayer involvement. The wallet's funds and key authority are
entirely yours.

#### B.3 Decrypt each on-chain secret

For every vault-bound secret you stored (via `outlayer secrets set
--vault-id <vault>` or the dashboard):

```bash
# 1. Fetch the encrypted ciphertext from the contract.
ARGS=$(jq -n --arg pid 'alice.near/my-project' --arg owner 'alice.near' --arg profile 'prod' \
    '{accessor: {Project: {project_id: $pid}}, profile: $profile, owner: $owner}')
ARGS_B64=$(printf '%s' "$ARGS" | base64 | tr -d '\n')
CIPHERTEXT=$(curl -s https://rpc.mainnet.fastnear.com -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"outlayer.near\",\"method_name\":\"get_secrets\",\"args_base64\":\"$ARGS_B64\"}}" \
    | jq -r '.result.result | implode' \
    | jq -r '.encrypted_secrets')

# 2. Decrypt with the recovered master + project seed.
./scripts/customer-recovery/target/release/customer-recovery decrypt-secret \
    --master "$MASTER_HEX" \
    --seed 'project:alice.near/my-project:alice.near' \
    --ciphertext-base64 "$CIPHERTEXT"
```

Output is the original plaintext JSON object you stored
(`{"KEY":"value", ...}`).

The seed format is fixed per accessor variant:
- **Project** (`outlayer secrets set --project owner/name`):
  `project:<owner>/<name>:<owner>`
- **Repo** (`--repo github.com/...`):
  `<repo>:<owner>:<branch>` or `<repo>:<owner>` if branch is wildcard
- **WasmHash** (`--wasm-hash <sha256>`):
  `wasm_hash:<hash>:<owner>`

`customer-recovery decrypt-secret` auto-detects the wire format
(ECIES v1 if the first byte is `0x01`, legacy ChaCha20-Poly1305
otherwise) and runs whichever matches. Dashboard-stored secrets and
secrets stored via current `outlayer-cli` (post-v0.1) use ECIES;
both work.

---

## What survives the exit

After the procedure:

| Artifact | You have | OutLayer has |
|---|---|---|
| Vault's NEAR account with funds | full-access key | nothing |
| Per-vault master (HKDF-stretched 32 bytes) | offline | evicted from TEE memory, cannot regenerate |
| Wallet ed25519 private keys | derivable from master + wallet_id | derivable from master, which they don't have |
| On-chain ciphertext of secrets | readable + decryptable | readable but cannot decrypt |
| `parent` field on the vault | unchanged (still your account) | irrelevant — no keys |
| Trust in OutLayer | not required for anything above | n/a |

---

## What you give up

- **OutLayer's keystore signing API** — `/wallet/v1/sign-message`,
  `/wallet/v1/transfer`, etc. return HTTP 5xx on every request that
  touches this vault. You sign locally instead.
- **`/call/<owner>/<project>` execution against vault-bound
  secrets** — the coordinator pre-check refuses at HTTP 423 in
  under a second. WASI execution that doesn't need vault-bound
  secrets is unaffected (the legacy default-master path still
  works).
- **The OutLayer dashboard** — vault detail pages will show
  `UNLOCKED (recovered)`. There is no "re-enrol" flow on chain;
  unlock is one-way by design.

You can deploy a **new** vault under the same parent at any time
and start fresh on the OutLayer side, but the unlocked vault stays
unlocked forever.

---

## What if someone front-ran me?

Short answer: they couldn't.

`finalize_recovery` is parent-only as of vault contract `v1.1`. The
contract requires
`env::predecessor_account_id() == self.parent` as its very first
action. Even if a malicious watcher polled `recovery` state and
saw your `finalize_after` elapse, calling `finalize_recovery` from
a non-parent account panics with `only the parent account can
finalize recovery` and leaves state untouched. You can finalize at
your leisure within the `finalize_before` window
(`finalize_after + FINALIZE_WINDOW`).

`initiate_unilateral_recovery` is also parent-only — only you can
start the timer in the first place.

`initiate_recovery` (the cessation path) is permissionless, but
the `is_ceased()` cross-contract check in `callback_initiate` will
refuse if the DAO hasn't actually declared cessation. So a
malicious actor can't start a cessation flow against an active
DAO.

---

## Trade-off the design makes

If your **parent account becomes unavailable** (lost key, deceased
operator, lost multisig signers), the vault stays locked forever
even after DAO cessation. This is the deliberate trade-off — the
alternative (anyone-can-finalize-cessation) would open a vault-
hijack vector where a third party substitutes their own pubkey at
finalize time and captures the vault.

For high-value deployments, configure parent-account social
recovery / multisig out-of-band so this risk is bounded.

---

## Verification check-list (for auditors)

The sovereign-exit guarantee rests on five contract-level properties.
Each is testable independently:

1. **Parent-only `finalize_recovery`** — `require!(predecessor ==
   self.parent)` at the top of the method. Sandbox test:
   `vault-contract/tests/integration.rs::unilateral_finalize_rejects_non_parent_after_window`.
2. **Atomic key-swap** — `dispatch_swap` issues
   `DeleteKey(*) + AddFullAccessKey(new_parent_pubkey)` in a single
   Promise; state mutation deferred to `callback_after_swap` and
   gated on swap success. Sandbox test:
   `unlocked_add_key_actually_adds_full_access_key_after_recovery`.
3. **Keystore refuses unlocked vaults** —
   `keystore-worker/src/api.rs` `ensure_customer_loaded` calls
   `assert_serving_allowed` which view-calls `vault.get_state()`
   and rejects on `unlocked == true`. Eviction also fires.
4. **Coordinator fast-fails unlocked vaults** —
   `outlayer-coordinator/src/handlers/call.rs`
   `assert_secret_vault_serving_allowed` runs BEFORE
   `create_execution_task`; HTTP 423 within 1 s instead of 100 s.
5. **MPC CKD is deterministic** — same `(predecessor_id,
   derivation_path)` produces the same secret, so
   `customer-recovery --from-chain` reaches the identical master
   OutLayer's keystore used.

End-to-end sovereignty proof on real testnet runs via
[`tests/sovereignty_e2e.sh`](../tests/sovereignty_e2e.sh) — 14
steps from `vault init` through sovereign send-near using the
locally-derived wallet key.

---

## Files referenced from this document

| Path | Purpose |
|---|---|
| [`scripts/customer-recovery/`](../scripts/customer-recovery/) | Standalone MPC CKD + key derivation + secret decrypt tool |
| [`scripts/customer-recovery/walkthrough.sh`](../scripts/customer-recovery/walkthrough.sh) | One-shot interactive runbook (recommended) |
| [`scripts/customer-recovery/README.md`](../scripts/customer-recovery/README.md) | Detailed CLI reference for the binary |
| [`tests/sovereignty_e2e.sh`](../tests/sovereignty_e2e.sh) | End-to-end test of this whole procedure |
| [`tests/vault_detach_test.sh`](../tests/vault_detach_test.sh) | Run the detach half against an existing vault+secret |
| [`vault-contract/src/lib.rs`](../vault-contract/src/lib.rs) | Contract source — search `finalize_recovery`, `dispatch_swap`, `callback_after_swap` |
| [`outlayer-coordinator/src/handlers/call.rs`](https://github.com/out-layer/outlayer-coordinator) | Coordinator-side vault-unlock fast-fail (separate repo) |
