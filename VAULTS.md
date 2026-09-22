# Sovereign Vaults — Architecture & Recovery Procedure

OutLayer's per-customer master keys with on-chain recoverability.
This document describes the **architecture**, the **trust model**,
and the two **recovery procedures** in detail. For the customer-facing
how-to, see `dashboard/app/docs/vaults/page.tsx` (rendered at
`/docs/vaults` on the dashboard) or `outlayer vault --help`.

## Why vaults exist

By default, every wallet key and encrypted secret on OutLayer is
derived from a shared **OutLayer master**, held inside the
keystore-worker's TEE. Convenient: zero customer setup, shared
infrastructure cost, automatic key rotation across keystore-worker
upgrades. The trust model is "OutLayer is honest" — if OutLayer
shuts down or its keystore-DAO loses quorum, customers' derived keys
are gone.

A **vault** replaces that shared master with a per-customer master
derived via NEAR's MPC network, recoverable by the customer through
two independent escape hatches:

1. **Cessation recovery** — OutLayer's DAO declares
   `is_ceased() == true`; anyone can drive the recovery; fixed
   7-day delay before finalization.
2. **Unilateral recovery** — the customer's parent NEAR account
   exits at any time without DAO involvement; configurable 24h-30d
   delay.

After either recovery completes, the vault is `unlocked` and the
parent account can install full-access keys and migrate funds.

## Components

| Layer | Responsibility | Path |
|---|---|---|
| **Vault contract** | Per-customer NEAR sub-account holding the TEE function-call key + recovery state machine | `vault-contract/` |
| **Keystore-DAO** | Whitelists vault WASM hashes (multisig-gated, see [F4 audit fix](#governance-fixes)), tracks `verified_vaults`, `banned_vaults`, `ceased_operations` | `keystore-dao-contract/src/lib.rs` |
| **Vault-checker WASI** | Public open-source agent that re-verifies vault state in TEE and forwards to keystore-worker | `wasi-examples/vault-checker/` |
| **Keystore-worker** | Multi-customer master cache with lazy MPC CKD load; `/sign-vault-verification` + `/admin/ban-vault` + `/admin/evict-customer` | `keystore-worker/src/api_support.rs` (cache and router in `api.rs`) |
| **Coordinator** | `/customer/derive-tee-key` + `/customer/sign-verification` + `/customer/register` + `/internal/vault-event` proxies | `outlayer-coordinator/src/wallet/handlers.rs` (separate repo) |
| **CLI** | `outlayer vault {init,resume,status,verify,initiate-recovery,...}` | `outlayer-cli/src/commands/vault.rs` (separate repo) |
| **Dashboard** | `/vault` management page + `<VaultScopeToggle/>` on secrets/wallet pages | `dashboard/app/vault/page.tsx`, `dashboard/lib/vault.ts` |
| **Race-attack monitor** | `near-lake-framework` consumer that detects duplicate `request_app_private_key` MPC calls and triggers `/admin/ban-vault` | `outlayer-monitor/` |

## Atomic deploy flow

The customer signs a single transaction with five actions that
either all succeed or all roll back:

```
receiver = vault.<customer.near>
actions  = [
    CreateAccount,
    Transfer(0.1 NEAR),                                 // storage stake (~0.004) + MPC-call gas reserve
    UseGlobalContract(approved_code_hash),              // NEP-591 — WASM lives in global registry, not on-account
    FunctionCall("new", {parent, keystore_dao,
                         mpc_contract, initial_exit_window}),
    AddKey(tee_function_call_key,
           FCAK on vault.request_master,
           allowance: Unlimited),
]
```

Why all-or-nothing matters: a half-deployed vault (account exists,
contract not initialised, or TEE key absent) would either be
unrecoverable (no key to drive MPC) or insecure (parent backup keys
still installed). Atomic deploy collapses every failure mode into
"sub-account never existed; retry safely".

After tx finality, three coordinator endpoints finish the flow:

1. `/customer/derive-tee-key {vault_id}` — fetched BEFORE deploy so
   the AddKey action installs the right TEE pubkey (deterministic
   HMAC of vault_id, computed inside the TEE).
2. `/customer/sign-verification {vault_id}` — keystore re-runs the
   five RPC checks defense-in-depth and submits
   `mark_vault_verified` on chain.
3. `/customer/register {vault_id, webhook_url?}` — coordinator
   confirms `is_vault_verified == true` and mints the API key.

## Two-layer key derivation

```
Layer 1 (TEE function-call key, HMAC-derived from OutLayer master):
    tee_keypair = HMAC(outlayer_master, "outlayer.near:{vault_id}")
    install pubkey on vault as FCAK on (mpc_contract, ["request_app_private_key"])

Layer 2 (per-vault master, MPC CKD called FROM the vault):
    secret_path = HMAC(outlayer_master, "vault-master:{vault_id}")
    master      = MPC.request_app_private_key(
                      signer=vault_id (Layer 1 keypair),
                      app_public_key=ephemeral,
                      derivation_path=secret_path,
                      domain_id=2)
```

Determinism: same vault_id + same OutLayer master → same secret_path
→ same MPC-derived master, regardless of which approved TEE worker
runs the derivation. After cessation, an approved-by-new-DAO TEE
worker can re-derive both layers and recover funds for the customer.

The `secret_path` is HMAC-derived so a malicious customer who copies
their own vault's MPC tx from the mempool cannot replay it from a
fake vault — the path itself is unguessable without the OutLayer
master.

## Trust model & race-attack mitigation

The end-user (the customer's customer) interacts with the customer's
app directly. The customer is the trusted party for their end-users;
OutLayer is the customer's TEE infrastructure provider, not a
counterparty to end-users. This shapes the recovery design:
**unilateral recovery** is a *customer* escape hatch, not an
end-user protection mechanism.

### Why initialization-time attacks don't compromise the master

A natural concern for end-users: "what if the customer is malicious
and rigs the vault during deploy to give themselves a backdoor?"

**Outcome: not possible by construction.** The vault becomes
immutable immediately after the atomic deploy:

- The atomic deploy is a single all-or-nothing NEAR transaction.
  Any half-baked state (malicious code, extra keys, tampered
  contract state) either rolls back entirely or produces a final
  state that vault-checker observably rejects.
- After the atomic deploy completes, the vault account holds **only
  the TEE function-call key**, restricted to
  `mpc_contract.request_app_private_key`. That key cannot
  `AddKey`, `DeployContract`, or call any method on the vault
  contract itself. The customer's parent account holds **no key on
  the vault account**.
- The approved vault contract has no method that calls
  `Promise::new(self).deploy_contract(...)` or
  `Promise::new(self).add_full_access_key(...)` — verified by the
  contract's audit checklist
  (`vault-contract/src/lib.rs:25-44`).
- Any Promises emitted during the atomic deploy run synchronously
  in the next 1-3 blocks. They cannot be timed to evade
  vault-checker's view-call (which runs at finality, after all
  emitted promises have completed).
- The per-vault `secret_path` is `HMAC(outlayer_master,
  "vault-master:{vault_id}")` — unguessable without TEE
  compromise. Even if a hostile customer pre-emits an MPC call
  with a chosen derivation_path, the resulting master is
  uncorrelated with the legitimate per-vault master and useless.

The only paths from "deployed, verified" back to "parent-controlled"
are the two recovery procedures below. Both impose explicit delays
(24h-7d minimum), and both are visible on chain through the
contract's `recovery` state field, which `outlayer vault verify`
surfaces.

### Post-recovery customer-fraud risk (end-user disclosure)

A malicious customer who deployed the vault honestly CAN regain
full control of the vault account through the unilateral recovery
flow:

1. Wait at least `unilateral_exit_window_secs` (24h-30d, set at
   deploy and visible on chain).
2. Call `unilateral_initiate_recovery`, wait the configured window,
   call `finalize_recovery`. Vault is now `unlocked`.
3. Call `unlocked_add_key(attacker_full_access)` — install a
   full-access key on the vault.
4. Sign a tx from the vault that calls
   `mpc_contract.request_app_private_key` with the same
   `derivation_path` the legitimate keystore-worker used.
5. Receive the same per-vault master — and with it every wallet
   key and every secret encrypted under that vault.

This is **not a vulnerability in OutLayer's TEE infrastructure** —
it's the customer exercising the sovereignty feature the vault was
built to provide. From the protocol's perspective, the customer was
ALWAYS able to recover their own vault; that's the entire point of
the unilateral exit window.

**Implication for end-users:**

- Treat the customer the same way you would treat them if they ran
  custody themselves: they CAN drain the vault after the configured
  exit window.
- Read `unilateral_exit_window_secs` via `outlayer vault verify
  <vault_id>` BEFORE depositing funds. The minimum is 24h, the
  maximum is 30 days. A customer with a long exit window has
  promised they will not exit for that long; a customer with the
  minimum 24h has reserved the option to exit quickly.
- `recovery` state on the vault is observable in real time. Tools
  that watch `vault.get_recovery_state()` can alert end-users the
  moment a recovery starts, providing
  `unilateral_exit_window_secs` of warning before the customer
  gains full control.
- For high-value, low-trust deployments, the customer can use a
  `parent` account controlled by a multisig or a contract that
  rate-limits `unilateral_initiate_recovery` calls. This shifts
  the trust assumption from "customer is honest" to "customer's
  multisig signers are honest", which may be acceptable for
  some applications.

OutLayer's role ends at the TEE boundary: keys are only ever
exfiltrated through (a) DAO cessation or (b) the customer's own
unilateral exit. End-users transacting with a customer's app are
trusting the customer's good faith for the duration of the
configured exit window, not OutLayer's.

### Race attack

A malicious customer could try to:

1. Sneak a backup full-access key into the atomic deploy.
2. Observe the keystore-worker's MPC `request_app_private_key` tx
   in the mempool.
3. Replay it from the vault account using their backup key BEFORE
   the keystore-worker submits `mark_vault_verified`.
4. Get the same per-vault master themselves; DeleteKey the backup
   to pass `vault-checker`'s access-key-list check.
5. Onboard end-users on a vault they secretly control.

### Mitigations

- **vault-checker** rejects any vault whose access-key-list is
  not exactly `[tee_pubkey]`. A customer who DeleteKey's their
  backup before verification can pass this check, so we add:
- **outlayer-monitor** subscribes to NEAR-lake receipts filtered by
  `(receiver=mpc_contract, method="request_app_private_key")`.
  Two calls from the same `(predecessor, derivation_path)` pair
  within 600 blocks (~10 minutes) trip
  `/admin/ban-vault {reason="duplicate_mpc_call_after_init"}`.
- **`/admin/ban-vault`** submits `keystore_dao.ban_vault(vault_id)`
  on chain AND evicts the in-memory cached master. Thereafter
  `is_vault_verified(vault_id)` returns false and any wallet
  operation referencing the banned vault is rejected at the
  lazy-load gate.
- **Detection window:** minutes (lake delivery + monitor latency)
  vs onboarding-fraud-damage window: days/weeks (time to attract
  end-users). DAO-driven recovery converges before damage scales.

## Recovery procedures in detail

### Cessation recovery

Used when OutLayer ceases operations and customers need their funds
back. Permissionless to start; gated entirely on DAO state.

```
DAO members → keystore_dao.declare_cessation()
              [ceased_operations = true]

Anyone     → vault.initiate_recovery()
              ↓ cross-contract is_ceased() check
              ↓ if true: recovery = {trigger: Cessation, finalize_after: now+7d}

(7-day delay)

Anyone     → vault.finalize_recovery()
              ↓ cross-contract is_ceased() check (re-checked, can be cancelled
              ↓ if DAO calls revoke_cessation in the window)
              ↓ if still ceased: unlocked = true, recovery = None

Parent     → vault.unlocked_add_key(parent_pubkey, full_access: true)
              [parent now controls the vault account directly;
               funds, secrets, and per-vault master are all derivable
               again because secret_path is recomputable by the
               post-cessation DAO-approved TEE]
```

If the DAO revokes cessation during the 7-day window, the recovery
state is cleared on the next `finalize_recovery` call and the vault
remains TEE-controlled. The customer can re-initiate after a fresh
`declare_cessation`.

### Unilateral recovery

Customer-driven voluntary exit. No DAO involvement.

```
Parent     → vault.set_exit_window(86400)             [optional, 24h-30d range]
Parent     → vault.unilateral_initiate_recovery()
              [recovery = {trigger: Unilateral,
                           finalize_after: now + unilateral_exit_window_secs}]

(configured delay — default 24h)

Anyone     → vault.finalize_recovery()
              [synchronous, no DAO check, no callback;
               unlocked = true, recovery = None]

Parent     → vault.unlocked_add_key(...)
```

The exit window is **frozen at initiate time** — calling
`set_exit_window` after `unilateral_initiate_recovery` only affects
future recoveries.

## Governance fixes

The keystore-DAO's vault-version registry uses the **proposal+vote
flow** (Phase 7 audit F4 fix). `approve_vault_version` and
`revoke_vault_version` require `approval_threshold` (>50% of DAO
members) distinct votes for the same `(action, hash, label, audit_url)`
tuple before executing; any single member alone records a vote and
returns its count. `deprecate_vault_version` is intentionally
single-member (soft signal, reversible by re-approving) so the DAO
can react quickly to a flagged hash without burning a full vote
cycle.

Vote ledger is `LookupMap<VaultVersionAction, Vec<AccountId>>` keyed
on the borsh-encoded full action tuple, so distinct
`(label, audit_url)` variants of the same hash are independent
proposals. Once a tuple's voter count reaches the threshold the
action executes and the entry is cleared; a late vote arriving
after execution starts a fresh proposal.

## Operational considerations

- **One-time cost:** ~0.1 NEAR transferred to the vault account at
  deploy time. With NEP-591 `UseGlobalContract` the WASM bytes live
  in the global registry, so storage stake collapses to the contract
  state (~0.004 NEAR for 391 bytes — three `AccountId`s, flags,
  empty `registered_tee_keys`). The remainder is gas reserve for
  outbound `vault.request_master → mpc.request_app_private_key`
  (~0.001 NEAR/call; the master is cached in keystore-worker enclave
  memory after the first call, so most vaults trigger MPC only a
  handful of times). Top up if you ever exhaust the reserve.
- **TEE key cap:** `Vault::MAX_REGISTERED_TEE_KEYS = 32`. Bricking
  this through griefing requires 32 distinct DAO-approved keystore
  pubkeys (each call costs the attacker gas and adds only
  legitimate keys); covers years of operational rotations. See
  `vault-contract/src/lib.rs::propose_tee_key` doc-comment.
- **Webhook subscriptions** (Phase 5 task 5): customers pass
  `webhook_url` to `/customer/register` to receive
  `vault_registered`, `vault_verified`, `recovery_*`, `vault_banned`,
  `vault_unbanned`, `vault_tee_key_added`, `exit_window_set` events.
  The coordinator emits `vault_registered` and `vault_verified`
  directly during its own request handling; on-chain transitions
  are forwarded by the `outlayer-monitor` crate (`LakeSource` reads
  FastNEAR's neardata feed, RPC-cross-checks each event, then POSTs
  to `/internal/vault-event`).
- **Email alerter:** intentionally deferred. Phase 8 plan listed
  "Slack/email integration"; the `outlayer-monitor` ships with
  `Slack`, `Telegram`, and `Stdout` alerters today. Email can be
  added as a fourth `Alerter` impl post-launch — operators
  comfortable with Slack/Telegram pipelines won't notice.

## Operator-side launch tasks

Items that require operator infra (live keys, DAO members, real
alpha-testers) are tracked outside this file. The local memory
note `~/.claude/projects/-Users-alice-projects-near-offshore/memory/project_vault_operator_debts.md`
is the canonical list — items there are the only deploy-day work
remaining.

## Cross-references

- `dashboard/app/docs/vaults/page.tsx` — customer-facing how-to
- `CUSTODY.md` — wallet custody overview with vault flow diagrams
- `tests/vault_e2e.sh` — automated scenarios (happy/isolation/compat)
- `/Users/alice/.claude/plans/partitioned-dreaming-patterson.md` —
  full implementation plan (internal)
