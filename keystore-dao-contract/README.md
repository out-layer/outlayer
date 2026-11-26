# Keystore DAO Contract

The NEAR contract that decides which keystore instances may obtain OutLayer's
shared master secret from the NEAR MPC network, and that holds the vault
registry (cessation flag, approved vault code hashes, verified and banned
vaults).

| Network | Contract | Owner | Init account | MPC contract |
|---|---|---|---|---|
| mainnet | `dao.outlayer.near` | `owner.outlayer.near` | `init-keystore.outlayer.near` | `v1.signer` |
| testnet | `dao.outlayer.testnet` | `owner.outlayer.testnet` | `init-keystore.outlayer.testnet` | `v1.signer-prod.testnet` |

Read the live configuration with `get_config`, `get_owner` and `get_dao_members`.

Source: `src/lib.rs` (contract), `src/governance.rs` (proposals, delay, blobs,
upgrades), `src/collateral.rs` (Intel collateral parsing, taken from the NEAR MPC
node), `src/migration.rs` (state migration).

## Governance

The DAO governs itself, the main contract (`outlayer.<net>`) and the register
contract (`worker.outlayer.<net>`). Whoever can change this contract's code
controls the master — MPC derives it for this account — so its members and its
delay are the root of trust. Every governance method is for DAO members only.

- **Proposals.** A member calls `propose(action)`; the proposer's vote is
  recorded with it. The proposal fixes its electorate (the members at that
  moment) and its threshold. A vote counts only from an account in that
  electorate that is still a member. Quorum makes it `Approved`.
- **Delay.** An approved proposal runs from `approved_at + gov_delay` — 72 h on
  mainnet, 0 on testnet; `SetDelay` changes it (at most 30 days). A member calls
  `execute(proposal_id)` once the delay has passed.
- **Expiry.** A proposal waits for votes at most 14 days, and an approved one is
  executed within 7 days after its delay. Past that, any member closes it with
  `expire(proposal_id)` — role replacements included, which the owner cannot
  cancel. An approved proposal is never executed long after it was voted for.
- **Storage.** `propose` is payable: the proposer pays the storage of the
  proposal and of the members' votes to come; the excess comes back. A `Call`'s
  `args` is at most 8 KB.
- **Actions:** `Upgrade{target, code_hash, migrate}` (this contract or a
  governed one), `Call{target, method, args, deposit, gas_tgas}` (a method on a
  governed contract; never this contract, never the MPC contract),
  `ApproveOsImage`, `RevokeOsImage`, `ApproveCompose`, `RevokeCompose`,
  `AddMember`, `RemoveMember`, `SetDelay`, `SetOwner`. `ApproveMeasurements` /
  `RevokeMeasurements` are no longer taken (a keystore build is its guest OS and
  its compose); a stored one still reads and does not execute.
- **The owner** (`owner_id`) cannot propose, vote or execute. It cancels a
  pending or approved proposal — except one that replaces a role (`SetOwner`, or a
  `Call` to `set_owner` / `set_governance` / `set_operator` on a governed
  contract), one that revokes a keystore build, a `Call` that revokes a worker build or key
  (`remove_approved_measurements`, `clear_all_approved_measurements`, `remove_worker_keys`),
  or a `SetDelay` that raises the delay,
  which members can only vote down — takes a keystore's guest OS, compose or measurements
  off the approved lists without a vote, keeps
  the Intel collateral current, rejects a pending keystore registration, and deletes
  keystore registrations that have been pending for more than 48 h.
- **The newer decision on a role wins.** A role is this contract's owner, a governed
  contract's owner, governance or operator (`SetOwner`, a `Call` to `set_owner` /
  `set_governance` / `set_operator`, per target), or one account's membership
  (`AddMember` / `RemoveMember`). Once a proposal has changed a role, an older proposal for
  the same role no longer executes, so an approved duplicate cannot undo a later decision.
  `get_last_role_change(role)` returns the id of the last one, `role` as
  `set_owner:<this account>`, `<method>:<target>` or `member:<account>`.
- **Upgrade gas.** A governed contract's `upgrade` / `upgrade_and_migrate` gets at least
  180 TGas and every unused TGas of `execute`, so a larger wasm needs only more gas on
  `execute`. An `Upgrade` never targets the MPC contract; `SetOwner` never names this
  contract.
- **Only keystore keys reach the master.** `request_key`, `request_escrow_key`,
  `store_escrow`, `mark_vault_verified` and the self-call of `ban_vault` require
  the call to come from this account AND be signed with a key in
  `approved_keystores` — a key installed by a registration vote. No other key on
  the account, a full-access key included, passes.
- **`request_key` yields the default master and nothing else**: it takes the
  empty derivation path and CKD domain 2 only. Every other path of this account
  names an owner's escrow key, released under the rules of
  [Owner exit](#owner-exit).

### Upgrades

Code reaches a vote as a blob. A member calls `store_blob()` with the wasm as
the raw input of the call (not JSON) and the storage deposit for its bytes; it
returns the wasm's sha256 — the code hash NEAR reports for the account after the
deploy, and the hash a reproducible build of the release gives. Members check
that hash against the release before they vote. An `Upgrade` proposal names it.

`execute` marks the proposal `Executed`, drops the blob (its deposit goes back
to the member who stored it) and dispatches the deploy: on this account as one
batch `deploy` [+ `migrate()`] + `gov_health()`, on another contract through its
`upgrade()` / `upgrade_and_migrate()` with the wasm as raw input. There is no
callback: `Executed` is the DAO's record, and whoever executed checks the
target. The batch is atomic: a failing `migrate`, or a state the new code
cannot read, leaves the old code; members then propose again. A `Call` cannot
reach `upgrade` or `upgrade_and_migrate`: code changes only as an `Upgrade`
naming a stored blob.

Proposals are stored versioned (`VersionedGovProposal::V1`). A released
variant is never changed or removed — a later version adds `V2` and keeps
reading `V1` — so every version reads what earlier ones wrote, and the DAO
upgrades itself whatever is open.

Every version keeps `migrate()` (called with `{}`) and `gov_health()`: an earlier
version calls them on a later one. `GovProposal` and `GovAction` are `V1`'s
shape and do not change.

### Deploying a release through the DAO

The same commands for the three contracts. `<target>` is the account being
upgraded and `<wasm>` its file:

| Contract | `<target>` | `<wasm>` |
|---|---|---|
| DAO | `dao.outlayer.near` | `keystore-dao-contract/target/near/keystore_dao_contract.wasm` |
| Main | `outlayer.near` | `contract/target/near/outlayer_contract.wasm` |
| Register | `worker.outlayer.near` | `register-contract/target/near/register_contract.wasm` |

Each member signs with their own key; `sign-with-keychain` below stands for
whichever signer they use.

**1. Build** — the proposer, and later every member who checks the proposal,
from a clean committed tree:

```bash
(cd contract && cargo near build reproducible-wasm)    # or keystore-dao-contract, register-contract
```

It prints the wasm's size and its sha256 in hex and in base58. The base58 one
is `<code_hash>`, the code hash NEAR shows for the account after the deploy.

**2. Store the wasm** — the proposer. The deposit is its storage: 0.00001 NEAR
per byte (8.76 NEAR for 876 KB); attach a little more, the excess comes back at
once, and the deposit itself comes back when the upgrade executes:

```bash
near contract call-function as-transaction dao.outlayer.near store_blob file-args <wasm> \
  prepaid-gas '100 Tgas' attached-deposit '<size × 0.00001 + 0.1> NEAR' \
  sign-as <member> network-config mainnet sign-with-keychain send
```

It returns `<code_hash>`.

**3. Propose** — the proposer. `migrate` is `true` for a release that changes
the state layout (the new code's `migrate()` runs in the same batch), else
`false`. The proposer's vote is counted with the proposal; the call returns
`<id>`:

```bash
near contract call-function as-transaction dao.outlayer.near propose \
  json-args '{"action":{"Upgrade":{"target":"<target>","code_hash":"<code_hash>","migrate":false}}}' \
  prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' \
  sign-as <member> network-config mainnet sign-with-keychain send
```

**4. Check and vote** — every other member. Rebuild the same commit (step 1)
and compare its base58 sha256 with the proposal's `code_hash` and the stored
blob:

```bash
near contract call-function as-read-only dao.outlayer.near get_gov_proposal json-args '{"proposal_id":<id>}' network-config mainnet now
near contract call-function as-read-only dao.outlayer.near get_blob json-args '{"hash":"<code_hash>"}' network-config mainnet now
near contract call-function as-transaction dao.outlayer.near vote json-args '{"proposal_id":<id>,"approve":true}' \
  prepaid-gas '100 Tgas' attached-deposit '0 NEAR' sign-as <member> network-config mainnet sign-with-keychain send
```

With three members, the proposer and one more vote approve it
(`approval_threshold = members / 2 + 1`). `get_gov_proposal` then shows
`Approved` and `executable_after`, 72 hours later (`get_gov_delay_sec`).

**5. Execute** — any member, after `executable_after`:

```bash
near contract call-function as-transaction dao.outlayer.near execute json-args '{"proposal_id":<id>}' \
  prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as <member> network-config mainnet sign-with-keychain send
```

**6. Check the result:**

```bash
near account view-account-summary <target> network-config mainnet now      # code hash = <code_hash>
near contract call-function as-read-only <target> gov_health json-args '{}' network-config mainnet now
near contract call-function as-read-only outlayer.near get_storage_version json-args '{}' network-config mainnet now
```

A failing deploy or `migrate` leaves the old code. The proposal is `Executed`
and its blob is gone: fix the release and start again from step 1. A proposal
that collects no quorum in 14 days, or is not executed within 7 days after its
delay, expires; the proposer then takes the blob back with `remove_blob`.

On testnet the accounts are `*.outlayer.testnet`, `network-config testnet`, and
the delay is 0: step 5 runs as soon as the proposal is approved.

## How a keystore obtains the master

```
keystore (Intel TDX)                     dao.outlayer.near                    MPC contract
  1. keypair in enclave memory
  2. TDX quote, report_data = key
  3. ── submit_keystore_registration ──►  verify quote, replay its event log:
     quote + boot event log               which compose, which instance;
     (signed by the init account)         create proposal
                                          4. DAO members vote for that key
                                          5. on approval: add a function-call
                                             key to its own account
  6. ── request_key (signed with that key) ──► request_app_private_key ──────►
  7. ◄──────────────── encrypted CKD response (big_y, big_c) ◄────────────────
  8. decrypt with the one-shot BLS key, verify the MPC signature, HKDF → master
```

1. The keystore generates its registration keypair (ed25519 or ml-dsa-65) in
   enclave memory. It is never written to disk; a restart generates a new one
   and needs a new vote.
2. It asks dstack for a TDX quote whose `report_data[0..32]` is the raw ed25519
   public key, or SHA-256 of an ml-dsa-65 public key.
3. The init account submits `submit_keystore_registration`. Only the init
   account may call it (it pays the gas). The contract:
   - refuses an ed25519 key of small order (no secret key exists for it, and
     near-crypto's verifier accepts signatures for it made without one);
   - refuses a key that is already approved;
   - picks the cached collateral whose FMSPC matches the quote and verifies the
     quote with `dcap-qvl` against it (no collateral may be passed in the call);
   - refuses any TCB status other than `UpToDate`, and any quote with
     outstanding Intel security advisories;
   - extracts MRTD and RTMR0–3;
   - replays the registration's boot event log (below) and requires the result
     to equal the quote's RTMR3;
   - requires the guest OS (MRTD, RTMR0–2) and the compose hash the log states
     to be approved by governance;
   - records what the log states: the compose hash, the app id, the instance
     id and the key provider (`get_registration_facts`);
   - answers with the id of the same key's registration when one is pending;
   - recomputes the `report_data` binding from the submitted key and requires
     it to equal the quote's;
   - creates a `Pending` proposal and returns its id.
4. DAO members call `vote(proposal_id, true, public_key)`, naming the key.
5. When enough current members approve, the contract checks the build again: if
   its guest OS or its compose was taken off the list while the registration
   waited (by the owner or by governance), the proposal ends `Rejected` and
   nothing is installed. Otherwise it adds the key to its own
   account as a function-call key: receiver = the contract itself, methods
   `request_key`, `mark_vault_verified`, `ban_vault`, **unlimited allowance**.
   The key goes into `approved_keystores` and the proposal ends `Executed`.
6. The keystore signs a transaction from the contract account with that key,
   calling `request_key(request)`. The contract forwards the request unchanged
   to the MPC contract's `request_app_private_key`, with 100 TGas and 1
   yoctoNEAR from its own balance. The keystore sends `derivation_path = ""`
   and a fresh BLS12-381 G1 public key as `app_public_key`; the contract does
   not inspect either.
7. MPC derives for `app_id = SHA3-256("near-mpc v0.1.0 app_id derivation:" ||
   predecessor || "," || derivation_path)`, where the predecessor is the DAO
   account. Every approved keystore therefore receives the same master.
8. The keystore decrypts the response, checks it against the MPC domain public
   key (`MPC_PUBLIC_KEY`) and stretches it to 32 bytes with HKDF.

The quote itself is not stored. The proposal records the measurements, the
submitter and the key; the quote's verification is visible in the
transaction's logs.

### The build is approved once; every instance takes a vote

TDX measures a CVM into five registers, and they answer different questions.

- **MRTD, RTMR0–2 — the guest OS**: firmware, its configuration, kernel, command
  line and initrd with the root filesystem's hash. The TDX module and the
  firmware write them; nothing in the guest can.
- **RTMR3 — written by that guest OS** at boot, one event per fact: the app id,
  the hash of the app's compose (the images by digest), the **instance id** of
  this very CVM, the key provider. So RTMR3 is not a build hash: two instances
  of one release share a compose hash and differ in RTMR3, and a redeployed CVM
  is a new instance with a new RTMR3.

A registration carries its RTMR3 events (`event_log`: dstack's entries with
`imr`, `event_type`, `event`, `event_payload`, as the quote API returns them;
a `digest` sent along is not read). The contract computes each event's digest
from its fields (`sha384(event_type ‖ ":" ‖ event ‖ ":" ‖ payload)`), replays
them, and takes the registration only when the result is the RTMR3 of the
verified quote: a changed field changes the register. It reads the facts from the events before `system-ready` —
those the guest OS wrote; an app may add events after it — each must be there
once and have the size dstack writes, and an event name carries no `:`.

An event log is evidence only under a known OS: under another one, anything can
extend RTMR3 with a real keystore's public log. Hence two approvals by
governance, each with the governance delay, each known before a CVM exists:

| What | Action | Changes |
|---|---|---|
| The guest OS: `{mrtd, rtmr0, rtmr1, rtmr2}` | `ApproveOsImage` / `RevokeOsImage` | per dstack version and platform |
| The release: `compose_hash` | `ApproveCompose` / `RevokeCompose` | per keystore release |

`compose_hash` is the sha256 of the CVM's app compose — the keystore's compose
file with its image pinned by digest, and the names of the environment
variables it may receive — the same for every instance of a version. The
compose is public (the CVM's guest agent and the attestation portal show it),
so a member reads what will run and checks the hash before voting.
`is_build_approved(measurements, compose_hash)` answers for both. The owner
takes either off the list at once (`remove_approved_os_image`,
`remove_approved_compose`): no keystore of it registers from then on, one whose
registration waits for votes included.

### The wallet contract builds keystores sign for

An agent in on-chain custody keeps its balance on an account that runs a wallet
contract, and a keystore gives its half of a signature only to an account whose
code hash is on the DAO's list. Keystores read the list on every request.

| What | Action | Changes |
|---|---|---|
| A build of the wallet contract: `code_hash`, as NEAR reports it for an account (base58) | `ApproveWalletContract` / `RevokeWalletContract` | per build of the wallet contract |

It is a list and not one value: an account stays on the build it was installed
with, so a later build is approved beside the earlier one. A build taken off the
list is refused from the next request; what lies on its accounts moves by their
own keys or through the owner's exit. The owner takes one off at once
(`remove_approved_wallet_contract`). `get_approved_wallet_contracts()` reads the
list.

An approved build says which code runs in the TD, not whose instance it is: the
keystore's environment (which workers and which coordinator it serves) is not
measured, and anyone with a TDX host can start the same build with their own.
That is what the members' vote on a registration decides, and why every
instance, and every restart of one (a new in-memory key), takes a vote:

- The operator who deployed the CVM reads its key from its own log and its
  measurements, instance id and compose hash from its own guest agent
  (`scripts/deploy_tdx.sh` does, reads only the current boot of a keystore that
  does not serve yet, and refuses a registration on chain that differs), and
  asks the members to vote **for that key**.
- A vote for a registration names its key: `vote(id, true, public_key)` is
  refused when registration `id` is for another key, and a vote for a
  registration without a key is refused. A member's vote cannot land on a
  registration somebody else submitted — a clone of the same build with the
  same instance id included — whatever id they were given and whichever
  registration came first.

The vote on a registration has no delay and counts the current members against
the current threshold; the delay stands in front of the build.

There is one way to register, with the event log: without it a quote says
which code runs only through an RTMR3 nobody can check. A registration stored
before registrations carried their log states no build, and a quorum on it
installs nothing.

## Voting

`approval_threshold = dao_members / 2 + 1`, set at `new` and recomputed when
an `AddMember` or `RemoveMember` proposal executes.

Registration, key-revocation and governance proposals share one id counter and
one `vote(proposal_id, approve, public_key?)` entry point; `public_key` goes
with a vote for a registration and with nothing else. Governance proposals follow the
rules in [Governance](#governance); the rest of this section is about
registration and revocation proposals. A member votes once per proposal.
After each vote the contract counts only votes from accounts that are members
at that moment:

- approve votes ≥ `approval_threshold` → the proposal executes;
- reject votes > `members − approval_threshold` → the proposal is `Rejected`;
- otherwise it stays `Pending`. Proposals do not expire.

The stored `votes_for` / `votes_against` count every vote ever cast, including
votes of members removed since; the decision never uses them.

Submitting a registration casts no vote. `propose_revoke_keystore_keys` records the proposer's approve vote in the
same call, so in a one-member DAO it executes immediately.

### Revoking keystore keys

`propose_revoke_keystore_keys(public_keys)` — DAO member only. Accepts 1 to 16
distinct keys, each of which must be in `approved_keystores`, so it can never
delete the full-access key or lock the account. On execution each key that is
still approved is removed from `approved_keystores` and deleted from the
account; a key already gone is skipped. A revoked instance keeps serving from
memory but cannot call `request_key` again or recover after a restart.

## Vault registry

| Method | Who | Effect |
|---|---|---|
| `declare_cessation()` / `revoke_cessation()` | any one DAO member | flips `ceased_operations`; vault contracts gate their recovery on `is_ceased()` |
| `approve_vault_version(hash, label, audit_url)` | DAO member, quorum | records the caller's vote for `hash`; at `approval_threshold` current members it adds `hash` to the approved set with its metadata (`deprecated = false`). The first voter's `label` / `audit_url` are locked: later voters must pass the same values or the call panics. Returns the vote count |
| `revoke_vault_version(hash)` | DAO member, quorum | same voting; at threshold removes the hash and its metadata |
| `deprecate_vault_version(hash)` | any one DAO member | sets `deprecated = true`; the hash stays approved. Re-approving through quorum clears it |
| `mark_vault_verified(vault_id)` | the contract account itself (an approved keystore's key) | adds the vault to `verified_vaults`; refused for a banned vault |
| `ban_vault(vault_id, reason)` | a DAO member, or the contract account itself | adds the vault to `banned_vaults`; `reason` (≤ 256 bytes) is logged only |
| `unban_vault(vault_id)` | any one DAO member | removes the ban |

A vault-version vote counts only current members: votes recorded by an account
removed since are dropped on the next vote. `label` is at most 64 bytes,
`audit_url` at most 256.

`mark_vault_verified` and `ban_vault` accept any approved keystore key equally.

## Owner exit

A NEAR account that owns agent wallets can leave OutLayer with its master
through this contract, with no keystore alive (`src/exit.rs`).

The keystore derives an owner's master inside the TEE from the default master
and the **owner path** `owner:{account}:{generation}`, and stores here an
**escrow** of it: the master encrypted under the MPC CKD key for that path, with
this contract as the predecessor. The contract builds the path itself — from the
caller's account, or from its stored record — and asks MPC for that key for two
callers only: an approved keystore, until the generation's escrow is stored, to
write it; and the owner, after the exit window, to open it. A successful claim moves the
owner to the next generation; the keystore stops serving the one that left.

| Method | Who | Effect |
|---|---|---|
| `register_exit_owner(exit_window_sec?)` | any account, with the registration fee attached (kept) | creates the caller's record at generation 1 |
| `set_exit_window(exit_window_sec)` | the owner, 1 yocto | a window at least as long as the one in force applies at once; a shorter one applies after the window in force has elapsed |
| `set_exit_approvers(approvers, threshold)` | the owner, 1 yocto | names the accounts whose quorum an exit needs. With no set in force: at once. With one in force: a pending action, in force once that set's quorum approved it. At most 16 accounts; an empty list with threshold 0 removes the set |
| `initiate_exit()` | the owner, with the exit fee attached (kept) | starts an exit from the current generation; needs that generation's escrow |
| `approve_exit(owner, nonce)` / `reject_exit(owner, nonce)` | an approver of that owner, 1 yocto | one vote on the pending action; one reject ends it |
| `cancel_exit()` | the owner, 1 yocto | drops the pending action |
| `claim_escrow_key(app_public_key)` | the owner, 1 yocto; MPC gets 100 TGas of the call's gas and the callback 30, so attach 300 TGas | inside the claim window, with the quorum when a set is in force: returns MPC's CKD answer for the generation being left, encrypted to `app_public_key` |
| `request_escrow_key(owner, app_public_key)` | the contract account, signed with an approved keystore key | MPC's CKD answer for the owner's current generation; refused once its escrow is stored |
| `store_escrow(owner, generation, ct, check)` | the same | stores the escrow; the first write stands, a later one answers `false` |
| `get_exit_owner(account)` | view | generation, exit window in force and a pending lowering, approvers, the pending action, `claim_in_flight`, the current generation's `escrow_check` |
| `get_escrow(account, generation)` | view | `{ct, check, domain_id}` |

- **One pending action per owner**: an exit, or a change of the approver set.
  While one is pending, starting the other is refused. An exit not claimed by
  its `finalize_before` no longer counts and the next action replaces it.
- **A claim is in flight from its call to its callback.** The claim marks the
  record before it calls MPC, because MPC's answer exists in MPC's own receipt
  whether or not the callback runs. While the mark stands, every method that
  writes the record is refused, votes included, and `get_exit_owner` reports
  `claim_in_flight`. The callback reads only whether MPC answered; it clears the
  mark, and on success clears the pending exit and adds 1 to the generation. A
  mark whose callback never ran stops counting after one hour.
- **A generation's key is released to its owner once.** `claim_escrow_key`
  returns MPC's answer as the transaction's result, and a claim that returned it
  leaves nothing to claim again.
- **A claim MPC did not answer is a failed claim.** The generation stays, the
  exit stays pending and the keystore keeps serving; the owner claims again
  inside the claim window. An answer MPC sends after its own timeout is in
  MPC's transaction and not in the claim's: the owner — who passed the window
  and the quorum to get that far — may then hold the key of a generation still
  served, until the next claim moves it on. The same holds for a mark that
  lapsed with no callback.
- **Every owner and approver method takes a deposit** — a fee or 1 yocto — so a
  function-call key on the account cannot call it.
- **A wallet cannot be the caller.** The contract takes its caller for an owner,
  and a wallet bound to an account acts as that account; the keystore's policy
  engine refuses every call to this contract from a wallet, under any policy
  (`KEYSTORE_DAO_CONTRACTS` in shared-tee-helpers), and a keystore starts only
  under a DAO that list names.
- **Timing follows the account**: on a `.near` account the exit window is
  24–48 h (default 24 h) and the claim window 7 days; elsewhere 60 s–1 h and
  10 minutes. `get_config().exit` shows the bounds and both fees.
- **Governance and the exit.** An upgrade that changes these rules waits the
  governance delay after the vote that approves it, and so does a proposal that
  shortens the delay: an owner who wants out starts an exit within
  `delay − their exit window` of that vote.

## Methods

### Init and migration

- `new(owner_id, init_account_id, dao_members, mpc_contract_id, gov_delay_sec?)`
  — `dao_members` must be non-empty; `gov_delay_sec` defaults to 72 h on a
  `.near` account and 0 elsewhere.
- `migrate(gov_delay_sec?)` — `#[private]`; reads the previous state layout and adds the
  governance state (no proposals, no blobs; the delay `gov_delay_sec`, or the default
  without it). `SetDelay` changes the delay afterwards. Run once after
  deploying a build whose state layout changed; until then every method panics
  on deserialization.

### Owner

- `cancel(proposal_id)` — a pending or approved governance proposal, not one
  that replaces the owner or the governance (`SetOwner`, a `Call` to `set_owner` /
  `set_governance`), revokes a keystore build, revokes a worker build or key (a `Call` to
  `remove_approved_measurements`, `clear_all_approved_measurements` or `remove_worker_keys`),
  or raises the delay. Of two approved
  `SetDelay` proposals the newer wins: an older one no longer executes after it.
- `remove_approved_os_image(image)`, `remove_approved_compose(compose_hash)` —
  registered keystores keep their keys; revoke those with
  `propose_revoke_keystore_keys`.
- `remove_approved_wallet_contract(code_hash)` — keystores stop signing for the
  accounts that run that build of the wallet contract.
- `update_collateral(collateral, index)` — `collateral` is the
  `QuoteCollateralV3` JSON as a string; `index` is the slot, `0` or `1` (at most
  two slots, one per platform FMSPC), at most 128 KiB each. A slot is replaced
  in place, and a new slot may only be the next index. The contract stores it
  as given; a registration verifies the quote against it.
- `reject_registration(proposal_id)` — a keystore registration still `Pending`
  becomes `Rejected` and no vote can install its key. A brake: it installs,
  approves and votes nothing, so its worst use is rejecting a good
  registration, whose keystore then restarts and submits again.
- `remove_stale_proposals(proposal_ids) -> u32` — deletes keystore registration
  proposals still `Pending` more than 48 h after they were made (a keystore
  stops waiting for its vote after 24 h); other ids are skipped.

### DAO members

- `propose(action) -> u64` (payable: the proposal's storage), `vote(proposal_id, approve, public_key?)`,
  `execute(proposal_id)`, `expire(proposal_id)`
- `store_blob()` — raw wasm input, attach the storage deposit; returns its sha256
- `remove_blob(hash)` — the member who stored it
- `propose_revoke_keystore_keys(public_keys) -> u64`
- the vault-registry methods above

### Init account

- `submit_keystore_registration(public_key, tdx_quote_hex, app_id?, event_log) -> u64` —
  `event_log` (required) is the quote's RTMR3 events; `app_id`, when given, is only logged.

### Contract account, signed with an approved keystore key

- `request_key(request) -> CKDResponse` — `request` is
  `{derivation_path, app_public_key, domain_id}`, forwarded to the MPC contract;
  `derivation_path` must be empty and `domain_id` 2.
- `request_escrow_key(owner, app_public_key)`, `store_escrow(owner, generation, ct, check)`
  — see [Owner exit](#owner-exit)
- `mark_vault_verified(vault_id)`, `ban_vault(vault_id, reason)`

### Views

- `get_proposal(proposal_id)`, `get_proposals(from_index, limit)` — registration
  proposals
- `get_registration_facts(proposal_id)` — `{compose_hash, app_id, instance_id,
  key_provider, os_image_hash}` of a registration made with an event log
- `get_revoke_proposal(proposal_id)`
- `is_keystore_approved(public_key)` — `public_key` as a string; an unparsable
  key returns `false`
- `get_approved_keystores(from_index, limit)`
- `get_approved_wallet_contracts()` — the wallet contract builds keystores sign for
- `get_approved_os_images()`, `get_approved_composes()`,
  `is_build_approved(measurements, compose_hash)` — hex accepted in either case and
  stored, revoked and compared in lowercase, as a quote is read
- `get_dao_members()`, `get_owner()`, `get_config()`
- `get_gov_proposal(proposal_id)`, `get_gov_proposals(from_index, limit)`,
  `get_gov_delay_sec()`, `get_blob(hash)`
- `get_collateral()` (slot 0), `get_collaterals()` (all slots)
- `is_ceased()`
- `is_vault_code_approved(hash)` — includes deprecated hashes
- `list_approved_vault_versions()`
- `get_vault_version_votes(action)` — `action` is `{"Approve": {"hash": "…"}}`
  or `{"Revoke": {"hash": "…"}}`
- `is_vault_verified(vault_id)` — verified and not banned
- `is_vault_banned(vault_id)`

## Examples

```bash
# Approved builds and pending work
near contract call-function as-read-only dao.outlayer.near get_approved_composes \
  json-args '{}' network-config mainnet now
near contract call-function as-read-only dao.outlayer.near get_approved_os_images \
  json-args '{}' network-config mainnet now
near contract call-function as-read-only dao.outlayer.near get_proposals \
  json-args '{"from_index": 1, "limit": 20}' network-config mainnet now

# Vote on a governance proposal (DAO member)
near contract call-function as-transaction dao.outlayer.testnet vote \
  json-args '{"proposal_id": 42, "approve": true}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as <member> network-config testnet sign-with-keychain send

# What a keystore registration states, then a vote for its key (DAO member)
near contract call-function as-read-only dao.outlayer.testnet get_registration_facts \
  json-args '{"proposal_id": 43}' network-config testnet now
near contract call-function as-transaction dao.outlayer.testnet vote \
  json-args '{"proposal_id": 43, "approve": true, "public_key": "ed25519:<the key the operator read from the CVM>"}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as <member> network-config testnet sign-with-keychain send

# Propose a member (DAO member), then a member executes it after the delay
near contract call-function as-transaction dao.outlayer.testnet propose \
  json-args '{"action": {"AddMember": {"member": "<account>"}}}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as <member> network-config testnet sign-with-keychain send
near contract call-function as-transaction dao.outlayer.testnet execute \
  json-args '{"proposal_id": 43}' \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as <member> network-config testnet sign-with-keychain send
```

The access keys on the account — which keys can call `request_key` — are read
with `near account list-keys dao.outlayer.near network-config mainnet now`.

## Build and test

```bash
./build-docker.sh   # cargo near build in sourcescan/cargo-near:0.22.0-rust-1.97.1
./build.sh          # local cargo near build; needs an LLVM clang/llvm-ar for the ring crate
cargo test          # unit tests
```

Both write `res/keystore_dao_contract.wasm` and are for development. The release
build is reproducible, from a clean committed tree, in the image pinned in
`Cargo.toml` (`[package.metadata.near.reproducible_build]`):

```bash
cargo near build reproducible-wasm   # target/near/keystore_dao_contract.wasm
```

Its sha256 is the `code_hash` a DAO upgrade proposal names; anyone rebuilding the
commit gets the same.

Production keystores are deployed with `scripts/deploy_tdx.sh keystore`, which
proposes the new build's measurements to the DAO (or executes the open proposal
once it is approved and its delay has passed) and votes on the keystore's
registration; see [keystore-worker/README.md](../keystore-worker/README.md).
A restarted keystore waits up to 24 h for its registration vote.

The governance suites run against a separate set of contracts on testnet:
[tests/dao/](../tests/dao/).

## License

Apache-2.0. `src/collateral.rs` is derived from
[near/mpc](https://github.com/near/mpc) under the MIT License.
