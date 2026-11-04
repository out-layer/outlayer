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

Source: `src/lib.rs` (contract), `src/collateral.rs` (Intel collateral parsing,
taken from the NEAR MPC node), `src/migration.rs` (state migration).

## Governance at this stage

Read this before the rest. The contract's checks are only as strong as the keys
around it:

- **Owner-only, no vote:** `add_approved_measurements`,
  `remove_approved_measurements`, `clear_all_approved_measurements`,
  `add_dao_member`, `remove_dao_member`, `update_collateral`. The owner decides
  which enclave builds may register and who votes. Because the owner sets
  membership, the owner can change who meets any threshold below.
- **`request_key` checks only that the caller is the contract account itself**
  (`predecessor_account_id == current_account_id`). Any key on the contract
  account passes that check: the function-call keys installed by a vote, and
  also a full-access key. `dao.outlayer.near` currently carries a full-access
  key, so its holder can obtain the shared master secret outside any enclave.
- **The contract upgrades by key.** There is no upgrade method and no vote:
  the account's full-access key deploys new code. `migrate` is `#[private]`
  and runs right after a deploy.
- **The DAO has one member**, so `approval_threshold` is 1 and every vote below
  passes on that member's single call.

Every use of these keys is a public NEAR transaction. See
[docs/NON_CUSTODIAL.md](../docs/NON_CUSTODIAL.md#governance-at-this-stage) for
what moves to the DAO before significant funds go through.

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
5. When enough current members approve, the contract adds the key to its own
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

`approval_threshold = dao_members / 2 + 1`, set at `new` and recomputed by
`add_dao_member` and `remove_dao_member`.

Registration and key-revocation proposals share one id counter and one
`vote(proposal_id, approve)` entry point. A member votes once per proposal.
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

`mark_vault_verified` and `ban_vault` trust every key on the contract account
equally: any approved keystore, and the full-access key, can call them.

## Methods

### Init and migration

- `new(owner_id, init_account_id, dao_members, mpc_contract_id)` — `dao_members`
  must be non-empty.
- `migrate()` — `#[private]`; reads the previous state layout and adds the
  `revoke_proposals` map. Run once after deploying a build whose state layout
  changed; until then every method panics on deserialization.

### Owner only

- `add_approved_measurements(measurements, clear_others?)` — each field is
  exactly 96 hex characters; `clear_others: true` drops every other entry first.
  Adding an existing entry is a no-op.
- `remove_approved_measurements(measurements)`
- `clear_all_approved_measurements()`
- `add_dao_member(member)` / `remove_dao_member(member)` — both recompute the
  threshold; `remove_dao_member` refuses when only one member is left.
- `update_collateral(collateral, index)` — `collateral` is the
  `QuoteCollateralV3` JSON as a string; `index` is the slot, `0` or `1` (at most
  two slots, one per platform FMSPC). A slot is replaced in place, and a new
  slot may only be the next index. Updating one slot leaves the other.

There is no method to transfer ownership.

### DAO members

- `vote(proposal_id, approve)`
- `propose_revoke_keystore_keys(public_keys) -> u64`
- the vault-registry methods above

### Init account

- `submit_keystore_registration(public_key, tdx_quote_hex, app_id?) -> u64` —
  `app_id`, when given, is only logged.

### Contract account (approved keystore keys)

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
- `get_approved_measurements()`, `is_measurements_approved(measurements)`
- `get_dao_members()`, `get_owner()`, `get_config()`
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

# Vote on a registration (DAO member)
near contract call-function as-transaction dao.outlayer.testnet vote \
  json-args '{"proposal_id": 42, "approve": true}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
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

Both write `res/keystore_dao_contract.wasm`. Both run
`cargo near build non-reproducible-wasm`, so the result is not a reproducible
build: a deployed code hash cannot be re-derived from this source with these
scripts.

Production keystores are deployed with `scripts/deploy_tdx.sh keystore`, which
approves the new build's measurements as the owner and votes on the resulting
proposal; see [keystore-worker/README.md](../keystore-worker/README.md).

## License

Apache-2.0. `src/collateral.rs` is derived from
[near/mpc](https://github.com/near/mpc) under the MIT License.
