# Sovereign Vaults — Architecture & Recovery Procedure

OutLayer's per-customer master keys with on-chain recoverability.
This document describes the **architecture**, the **trust model**,
and the two **recovery procedures**. The customer-facing how-to is
https://app.outlayer.ai/docs/vaults and `outlayer vault --help`; the
step-by-step exit runbook is [`docs/LEAVING_OUTLAYER.md`](docs/LEAVING_OUTLAYER.md).

## Why vaults exist

By default, every wallet key and encrypted secret on OutLayer is
derived from a shared **OutLayer default master**, held inside the
keystore-worker's TEE. Zero customer setup, shared infrastructure. The
only path back to those keys is an enclave that OutLayer's keystore
DAO approves.

A **vault** replaces that shared master with a per-customer master
derived through NEAR's MPC network from the customer's own account,
with two on-chain exits back to the customer:

1. **Cessation recovery** — the keystore DAO declares
   `is_ceased() == true`; anyone can start the recovery; fixed 7-day
   delay; the parent account finalizes.
2. **Unilateral recovery** — the customer's parent NEAR account
   exits at any time without DAO involvement, after an exit window
   chosen at deploy (1–30 days in the production build).

Finalizing either recovery atomically deletes every OutLayer key on
the vault and installs a key the parent supplies as the vault's only
full-access key.

## Components

| Layer | Responsibility | Path |
|---|---|---|
| **Vault contract** | Per-customer NEAR sub-account holding the TEE function-call key, the `request_master` MPC proxy and the recovery state machine | `vault-contract/` |
| **Keystore-DAO** | Whitelists vault WASM hashes, tracks `verified_vaults`, `banned_vaults`, `ceased_operations` | `keystore-dao-contract/src/lib.rs` |
| **Keystore-worker** | Per-vault master cache with lazy MPC CKD load and a per-request serving gate; `/derive-vault-tee-key`, `/sign-vault-verification`, `/admin/ban-vault`, `/admin/evict-customer`, `/admin/loaded-vaults` | `keystore-worker/src/mpc_ckd.rs`, `vault_verifier.rs`, `api_support.rs` (router in `api.rs`) |
| **Vault-checker WASI** | Open-source, independent implementation of the vault checks | `wasi-examples/vault-checker/` |
| **Coordinator** | `/customer/derive-tee-key`, `/customer/sign-verification`, `/customer/register`, `/register {vault_id}`, `/internal/vault-event`, and the `/call` vault-serving pre-check | `outlayer-coordinator` (private repo): `src/wallet/handlers.rs`, `src/handlers/call.rs` |
| **CLI** | `outlayer vault {init,resume,status,verify,initiate-recovery,initiate-unilateral-recovery,finalize-recovery,set-exit-window,unlocked-add-key}` | [outlayer-cli](https://github.com/out-layer/cli) `src/commands/vault.rs` |
| **Dashboard** | `/vault` management page; vault scope on the secrets and wallet pages | [dashboard](https://github.com/out-layer/dashboard) `app/vault/page.tsx`, `lib/vault.ts` |
| **Monitor** | Reads chain events: forwards vault log events to the coordinator, evicts cached masters on finalize, bans a vault on duplicate MPC calls | `outlayer-monitor/` |
| **Recovery tool** | Customer-side MPC CKD, wallet-key re-derivation, local secret decryption | `scripts/customer-recovery/` |

## Atomic deploy flow

The parent account signs a single transaction with five actions that
either all succeed or all roll back:

```
receiver = vault.<customer.near>
actions  = [
    CreateAccount,
    Transfer(1 NEAR),                       // storage (~0.004 NEAR) + standing gas reserve for MPC calls
    UseGlobalContract(approved_code_hash),  // NEP-591: the WASM lives in the global registry
    FunctionCall("new", {parent, keystore_dao, mpc_contract,
                         initial_tee_pubkey, initial_exit_window}),
    AddKey(tee_pubkey,
           FunctionCall { receiver: vault.<customer.near>,
                          methods: ["request_master"],
                          allowance: unlimited }),
]
```

`new()` requires the vault to be a direct sub-account of `parent`, so
a vault cannot name an unrelated account as its parent. The code hash
is the newest non-deprecated entry of
`keystore_dao.list_approved_vault_versions()`.

A half-deployed vault (account exists, contract not initialised, or
TEE key absent) cannot exist: every failure mode collapses into
"sub-account never existed; retry safely".

The CLI calls two coordinator endpoints around the deploy:

1. `POST /customer/derive-tee-key {vault_id}` — BEFORE the deploy, so
   the `AddKey` action installs the right TEE pubkey (deterministic,
   computed inside the TEE; see Layer 1 below).
2. `POST /customer/sign-verification {vault_id}` — AFTER the deploy.
   The keystore re-runs its vault checks (`vault_verifier.rs`: not
   banned, code hash approved, exactly one access key and it is the
   `request_master` function-call key, `unlocked == false`, no
   recovery in flight, expected `keystore_dao`) and submits
   `mark_vault_verified` on the DAO contract.

`outlayer vault resume <vault>` re-runs step 2 idempotently. Custody
wallets are minted separately, any number per vault, with
`POST /register {"vault_id": "<vault>"}` (returns `wallet_id`,
`api_key`, `near_account_id`) or `POST /customer/register
{"vault_account_id": "<vault>", "webhook_url": "..."}`; both require
`is_vault_verified == true`.

## Two-layer key derivation

```
Layer 1 (TEE function-call key, derived from the OutLayer default master):
    tee_keypair = ed25519(HMAC-SHA256(default_master, "outlayer.near:{vault_id}"))
    installed on the vault as a function-call key on (vault, ["request_master"])

Layer 2 (per-vault master, MPC CKD called FROM the vault):
    derivation_path = hex(HMAC-SHA256(default_master, "secret-path:vault-master:{vault_id}"))
    tx: signer = vault_id (Layer 1 key) → vault.request_master({request})
        → mpc_contract.request_app_private_key({derivation_path,
                                                app_public_key = ephemeral BLS12-381 G1,
                                                domain_id = 2}), 1 yoctoNEAR from the vault
    app_id = SHA3-256("near-mpc v0.1.0 app_id derivation:" + vault_id + "," + derivation_path)
    master = HKDF-SHA256(decrypted 48-byte G1 secret) → 32 bytes
```

`request_master` accepts only `predecessor == current_account_id`
(a transaction signed by a key on the vault itself), and refuses once
the vault is unlocked. The proxy exists because MPC requires 1
yoctoNEAR and a function-call key cannot attach a deposit.

Determinism: same vault id + same default master → same
derivation path → same MPC-derived master, whichever approved keystore
runs the derivation. MPC binds the result to the predecessor (the
vault account), so the same path from another account yields an
unrelated secret.

The derivation path is unguessable before the keystore's first CKD
call and is public in that call's arguments afterwards. Knowing it
gives nothing without the ability to sign a transaction as the vault.

Wallet keys and secret-encryption keys under a vault use the same
recipes as the default master, with the per-vault master as the HMAC
key: `wallet:{wallet_id}:near` (ed25519), `wallet:{wallet_id}:evm`
(secp256k1, one key for every EVM chain), `wallet:{wallet_id}:solana`
(ed25519); secrets use ECIES with the recipient key derived from
`"ecies:" + seed`.

## Serving gate

On every operation that names a vault, the keystore reads the chain
before it serves (`mpc_ckd.rs::ensure_customer_loaded` →
`assert_serving_allowed`):

- `keystore_dao.is_vault_verified(vault)` — false for unverified and
  banned vaults;
- `vault.get_state().unlocked == false`.

Either failing evicts the cached master and refuses. The CKD call is
made only after both pass, so the master is first derived after
`mark_vault_verified`. The coordinator runs the same two checks on
`/call` for Project-bound secrets that carry a vault binding and
answers `423 Locked` for an unlocked vault, `403` for an unverified
one.

## Trust model

### What the vault guarantees

- After the atomic deploy the vault holds **only** the TEE
  function-call key, restricted to `vault.request_master`. That key
  cannot add keys, deploy code, transfer funds, or call any other
  method. The parent holds **no key on the vault account**.
- The approved contract has no method that deploys code, and adds
  keys only in `callback_add_tee_key` (DAO-approved keystore keys,
  function-call on `request_master` only, max 32) and in the
  recovery swap / `unlocked_add_key` (parent, after unlock). Audit
  checklist: `vault-contract/src/lib.rs` module doc.
- Every derivation of the per-vault master is a transaction on the
  customer's own vault account, visible in its history.
- The only paths from "deployed, verified" to "parent-controlled" are
  the two recoveries below. Both impose a delay (exit window ≥ 1 day;
  cessation 7 days) and are visible on chain in `get_state().recovery`,
  which `outlayer vault status` prints.

### What it does not guarantee at this stage

The Layer 1 key and the derivation path are derived from the OutLayer
default master. A keystore build the DAO approves can therefore derive
any locked vault's TEE key and obtain its per-vault master through
`request_master`. Today approving keystore measurements is owner-only,
the DAO has one member and its account also has a full-access key
(see [NON_CUSTODIAL.md — Governance at this stage](docs/NON_CUSTODIAL.md#governance-at-this-stage)).
So while a vault is locked, the customer still trusts OutLayer's
governance not to approve a build that misuses a master. What the
vault adds is that every such derivation is a public transaction on
the customer's account, and that the customer can leave without
OutLayer's cooperation.

Recovery does not rotate keys: the master the customer recovers is
the master the keystore used, and every wallet keeps its address. A
customer who leaves because they distrust a past keystore build should
move funds to fresh keys after recovering.

### Customer vs end-user

The end-user (the customer's customer) interacts with the customer's
app. OutLayer is the customer's TEE infrastructure provider, not a
counterparty to end-users. **Unilateral recovery is a customer escape
hatch, not an end-user protection.** A customer can regain full
control of the vault:

1. Call `unilateral_initiate_recovery`, wait
   `unilateral_exit_window_secs` (set at deploy, on chain).
2. Call `finalize_recovery(new_pubkey)` — the vault now has the
   customer's full-access key and no OutLayer key.
3. Sign `mpc_contract.request_app_private_key` from the vault with the
   public derivation path and receive the per-vault master — and with
   it every wallet key and every secret encrypted under that vault.

That is the sovereignty feature working as designed. For end-users:

- Treat the customer as you would if they ran custody themselves:
  after the exit window they CAN move the funds.
- Read `unilateral_exit_window_secs` via `outlayer vault status
  <vault_id>` BEFORE depositing. A long window is a promise not to
  exit for that long; the 1-day minimum reserves a quick exit.
- `get_recovery_state()` is observable in real time; a watcher gets
  the full exit window of warning before the customer gains control.
- A `parent` controlled by a multisig or a contract shifts the trust
  from "the customer" to "the customer's signers".

### Duplicate-derivation monitor

`outlayer-monitor` watches `request_app_private_key` receipts to the
MPC contract. Two receipts with the same `(predecessor vault,
derivation_path)` within 600 blocks (~10 minutes; configurable) trigger
the keystore's `/admin/ban-vault` (which submits
`keystore_dao.ban_vault` and evicts the cached master) and an alert
(Slack, Telegram or stdout). A banned vault fails `is_vault_verified`
and is refused by the serving gate; `unban_vault` is DAO-member-only.

The same monitor forwards vault log events (`recovery_*`,
`exit_window_set_*`, `vault_tee_key_added`, …), each re-checked against
RPC, to the coordinator's `/internal/vault-event`, and on
`recovery_finalized_*` asks the keystore to evict that vault's master.
The serving gate refuses an unlocked vault on its own; eviction only
clears memory sooner.

## Recovery procedures

### Cessation recovery

Used when OutLayer stops operating. Starting it is permissionless and
gated on DAO state; finalizing it is parent-only.

```
DAO member → keystore_dao.declare_cessation()
              [ceased_operations = true; any single DAO member, reversible]

Anyone     → vault.initiate_recovery()
              ↓ cross-contract is_ceased() check
              ↓ if true: recovery = {trigger: Cessation,
                                     finalize_after: now + 7d,
                                     finalize_before: finalize_after + 7d}

(7-day delay)

Parent     → vault.finalize_recovery(new_parent_pubkey)
              ↓ is_ceased() re-checked; if the DAO revoked cessation,
              ↓ the recovery is cleared and the vault stays locked
              ↓ else: atomic batch on the vault account —
              ↓   DeleteKey(initial_tee_key), DeleteKey(each registered TEE key),
              ↓   AddFullAccessKey(new_parent_pubkey)
              ↓ callback_after_swap: unlocked = true, recovery = None
```

After a revocation the recovery can be started again once cessation is
declared again.

### Unilateral recovery

Customer-driven exit. No DAO involvement.

```
Parent     → vault.set_exit_window(secs)             [optional; 1d–30d; future recoveries only]
Parent     → vault.unilateral_initiate_recovery()
              [recovery = {trigger: Unilateral,
                           finalize_after: now + unilateral_exit_window_secs,
                           finalize_before: finalize_after + 7d}]

(exit window)

Parent     → vault.finalize_recovery(new_parent_pubkey)
              [same atomic key swap as above, no DAO check]
```

Common rules (both triggers):

- One recovery at a time.
- The window is frozen at initiate time; `set_exit_window` during a
  recovery only affects later ones.
- Finalizing before `finalize_after` panics with no state change.
- A finalize after `finalize_before` clears the recovery (the vault
  stays locked) and must be started again.
- If the swap batch fails (e.g. `new_parent_pubkey` already on the
  account), state is unchanged and the parent can retry with another
  key inside the window.
- If the parent account is lost, the vault stays locked forever, even
  after cessation. Finalize is parent-only so that no one watching the
  chain can substitute their own key.

`unlocked_add_key` adds further keys after unlock (parent only).

## Governance

The DAO's vault-version registry is quorum-gated:
`approve_vault_version(hash, label, audit_url)` and
`revoke_vault_version(hash)` execute when `approval_threshold` (>50%
of DAO members) distinct members have voted. Votes are keyed on the
hash; the first proposer's `(label, audit_url)` is locked and later
voters must pass the same values. Votes from accounts no longer in the
DAO are dropped before counting. `deprecate_vault_version` is
single-member: deprecation keeps the hash approved (existing vaults
keep working) and only steers new deployments away from it.
`declare_cessation`, `revoke_cessation` and `unban_vault` are
single-member.

With the DAO at one member, every one of these is a single-signer
action today, and the DAO account's full-access key can change the
contract itself.

## Operational considerations

- **Balance:** `outlayer vault init` transfers 1 NEAR to the vault.
  Storage is ~0.004 NEAR (state only; the WASM is a global contract).
  The rest is a standing reserve: each `request_master` call must
  prepay its attached gas from the vault's balance (most of it is
  refunded), and the keystore re-derives the master after every
  keystore restart, because the cache lives in enclave memory. A vault
  that cannot cover the prepayment cannot derive its master; top it up.
- **TEE key cap:** `MAX_REGISTERED_TEE_KEYS = 32`. `propose_tee_key` is
  permissionless but accepts only DAO-approved keystore keys; the
  parent can free slots with `clear_unused_tee_keys`.
- **Webhooks:** `POST /customer/register` takes `webhook_url`. The
  coordinator sends `vault_registered` and `vault_verified` itself;
  on-chain transitions (`recovery_initiated_*`, `recovery_finalized_*`,
  `recovery_window_expired`, `recovery_cancelled_dao_revoked`,
  `exit_window_set`, `vault_banned`, `vault_unbanned`,
  `vault_tee_key_added`) arrive through `outlayer-monitor` →
  `/internal/vault-event`.

## Cross-references

- https://app.outlayer.ai/docs/vaults — customer-facing how-to
- [`docs/LEAVING_OUTLAYER.md`](docs/LEAVING_OUTLAYER.md) — sovereign exit runbook
- [`docs/NON_CUSTODIAL.md`](docs/NON_CUSTODIAL.md) — custody and governance model
- [`vault-contract/README.md`](vault-contract/README.md) — contract API, events, build
- [`scripts/customer-recovery/README.md`](scripts/customer-recovery/README.md) — recovery tool
- `tests/vault_e2e.sh`, `tests/vault_recovery_e2e.sh` — CLI deploy and contract recovery state machine on testnet
- `tests/unified_vault_e2e.sh` (V1–V6) — isolation, multi-wallet, sovereign exit with offline re-derivation, secret decryption after recovery
