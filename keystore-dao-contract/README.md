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
  `ApproveMeasurements`, `RevokeMeasurements`, `AddMember`, `RemoveMember`,
  `SetDelay`, `SetOwner`.
- **The owner** (`owner_id`) cannot propose, vote or execute. It cancels a
  pending or approved proposal — except one that replaces a role (`SetOwner`, or a
  `Call` to `set_owner` / `set_governance` / `set_operator` on a governed
  contract), which members can only vote down — revokes keystore builds without a vote, keeps
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
- **Only keystore keys reach the master.** `request_key`, `mark_vault_verified`
  and the self-call of `ban_vault` require the call to come from this account
  AND be signed with a key in `approved_keystores` — a key installed by a
  registration vote. No other key on the account, a full-access key included,
  passes.

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

Every version keeps `migrate()` (no arguments) and `gov_health()`: an earlier
version calls them on a later one. `GovProposal` and `GovAction` are `V1`'s
shape and do not change.

`scripts/dao_upgrade.sh` stores the blob, proposes, votes and executes when the
delay has passed.

## How a keystore obtains the master

```
keystore (Intel TDX)                     dao.outlayer.near                    MPC contract
  1. keypair in enclave memory
  2. TDX quote, report_data = key
  3. ── submit_keystore_registration ──►  verify quote, check measurements,
     (signed by the init account)         create proposal
                                          4. DAO members vote
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
   - refuses a key that is already approved;
   - picks the cached collateral whose FMSPC matches the quote and verifies the
     quote with `dcap-qvl` against it (no collateral may be passed in the call);
   - refuses any TCB status other than `UpToDate`, and any quote with
     outstanding Intel security advisories;
   - extracts MRTD and RTMR0–3 and requires the five together to match one
     entry of `approved_measurements`;
   - recomputes the `report_data` binding from the submitted key and requires
     it to equal the quote's;
   - creates a `Pending` proposal and returns its id.
4. DAO members call `vote(proposal_id, approve)`.
5. When enough current members approve, the contract checks the build again: if its
   measurements were revoked while the registration waited (by the owner or by a
   `RevokeMeasurements` proposal), the proposal ends `Rejected` and nothing is installed.
   Otherwise the contract adds the key to its own
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

## Voting

`approval_threshold = dao_members / 2 + 1`, set at `new` and recomputed when
an `AddMember` or `RemoveMember` proposal executes.

Registration, key-revocation and governance proposals share one id counter and
one `vote(proposal_id, approve)` entry point. Governance proposals follow the
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

## Methods

### Init and migration

- `new(owner_id, init_account_id, dao_members, mpc_contract_id, gov_delay_sec?)`
  — `dao_members` must be non-empty; `gov_delay_sec` defaults to 72 h on a
  `.near` account and 0 elsewhere.
- `migrate()` — `#[private]`; reads the previous state layout and adds the
  governance state (no proposals, no blobs, the default delay). Run once after
  deploying a build whose state layout changed; until then every method panics
  on deserialization.

### Owner

- `cancel(proposal_id)` — a pending or approved governance proposal, not one
  that replaces the owner or the governance (`SetOwner`, a `Call` to `set_owner` /
  `set_governance`).
- `remove_approved_measurements(measurements)`, `clear_all_approved_measurements()`
  — registered keystores keep their keys; revoke those with
  `propose_revoke_keystore_keys`.
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

- `propose(action) -> u64` (payable: the proposal's storage), `vote(proposal_id, approve)`,
  `execute(proposal_id)`, `expire(proposal_id)`
- `store_blob()` — raw wasm input, attach the storage deposit; returns its sha256
- `remove_blob(hash)` — the member who stored it
- `propose_revoke_keystore_keys(public_keys) -> u64`
- the vault-registry methods above

### Init account

- `submit_keystore_registration(public_key, tdx_quote_hex, app_id?) -> u64` —
  `app_id`, when given, is only logged.

### Contract account, signed with an approved keystore key

- `request_key(request) -> CKDResponse` — `request` is
  `{derivation_path, app_public_key, domain_id}`, forwarded to the MPC contract.
- `mark_vault_verified(vault_id)`, `ban_vault(vault_id, reason)`

### Views

- `get_proposal(proposal_id)`, `get_proposals(from_index, limit)` — registration
  proposals
- `get_revoke_proposal(proposal_id)`
- `is_keystore_approved(public_key)` — `public_key` as a string; an unparsable
  key returns `false`
- `get_approved_keystores(from_index, limit)`
- `get_approved_measurements()`, `is_measurements_approved(measurements)` — measurements
  are 96 hex characters each, accepted in either case and stored, revoked and compared in
  lowercase, as a quote is read
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
near contract call-function as-read-only dao.outlayer.near get_approved_measurements \
  json-args '{}' network-config mainnet now
near contract call-function as-read-only dao.outlayer.near get_proposals \
  json-args '{"from_index": 1, "limit": 20}' network-config mainnet now

# Vote on a registration or a governance proposal (DAO member)
near contract call-function as-transaction dao.outlayer.testnet vote \
  json-args '{"proposal_id": 42, "approve": true}' \
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
