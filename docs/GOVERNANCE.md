# Governance

OutLayer's three on-chain contracts are governed by a DAO. No account holds a key that can
change their code. The DAO members decide together, and every decision waits out a public delay.
An operations owner runs day-to-day settings. It can apply the brakes and adjust parameters, but
it cannot change what the contracts are, and the DAO can replace it at any time.

| Contract | Account (mainnet) | Role |
|---|---|---|
| Keystore DAO | `dao.outlayer.near` | The governance root: members, proposals, the keystore builds allowed to obtain the master secret |
| Main | `outlayer.near` | Execution requests, payments, projects, secrets, wallet policies |
| Register | `worker.outlayer.near` | The TEE workers: which builds may run, and their keys |

## No full-access keys

None of the three accounts has a full-access key. Nobody can deploy code to them, add a key, or
sign arbitrary transactions as them. The keys that remain are narrow function-call keys, each
installed by the contracts themselves:

- **Workers on `worker.outlayer.near`.** Each worker's key is added only after its Intel TDX
  attestation is verified on chain against a build the DAO approved. The key may call only the
  four methods a worker needs on `outlayer.near`: delivering results and settling payments.
- **Keystores on `dao.outlayer.near`.** Each keystore's key is added only by a DAO vote on its
  verified attestation, and only for a build the DAO approved. It may call only `request_key`
  (obtain the master secret through NEAR MPC), `mark_vault_verified` and `ban_vault`.

Read the keys yourself: `near account list-keys outlayer.near network-config mainnet now`.

## The DAO

- **Members.** Three accounts, each held by a different person. Any two of three approve a
  proposal (`approval_threshold = members / 2 + 1`, recomputed when membership changes).
  `get_dao_members` on `dao.outlayer.near` lists them.
- **Delay.** An approved proposal executes no earlier than 72 hours after the vote that approved
  it. Anyone watching the chain has three days to see what is coming.
- **Lifetime.** A proposal collects votes for at most 14 days. Once approved, it must be executed
  within 7 days after its delay. Past either, it expires.
- **Fixed electorate.** Each proposal records the members and the threshold at the time it was
  made. Adding or removing members cannot change the outcome of a vote already under way.
- **The newer decision wins.** Of two approved proposals that change the same role (an owner, a
  governance account, an operator, a membership), an older one can no longer execute after a newer
  one has.

### What only the DAO can do

| Action | How |
|---|---|
| Upgrade any of the three contracts, the DAO itself included | `Upgrade`: a member stores the wasm as a blob, members vote on its sha256 — the hash a reproducible build of the release gives — and after the delay the contract deploys it in one atomic step. A failing migration leaves the old code in place |
| Add or remove a DAO member | `AddMember`, `RemoveMember`. The last member cannot be removed |
| Change the delay | `SetDelay`, at most 30 days |
| Approve a keystore build (the builds that may obtain the master secret) | `ApproveMeasurements` |
| Approve a worker build | A `Call` to `add_approved_measurements` on the register |
| Replace the operations owner of any contract | `SetOwner`, or a `Call` to `set_owner` |
| Replace a contract's governance account or the main contract's operator | A `Call` to `set_governance` / `set_operator` |
| Change the stablecoin the main contract accepts | A `Call` to `set_payment_token_contract` |
| Move a balance held by the main contract (a rescue) | A `Call` to `gov_transfer` |
| Install a keystore's key | A vote on its registration. The build is checked again when the vote reaches quorum, so a build revoked in the meantime gets nothing |
| Revoke keystore keys | `propose_revoke_keystore_keys`, decided by the members' vote |

A `Call` proposal can reach only a contract the DAO governs, and never the DAO itself or the MPC
contract. Code changes only as an `Upgrade`, by its hash.

### What any single member can do
Each of these is a narrow switch, not a change of rules:
- Flag a customer vault as banned or unbanned.
- Mark an approved vault version deprecated.
- Declare or revoke cessation of operations, which opens the vaults' own recovery path for their customers.

## The operations owner

`owner.outlayer.near` runs the parts that must happen quickly or routinely. Waiting three days for
a vote would hurt users there: stopping a bad build at once, refreshing Intel's reference data
every month, setting prices.

Every owner power is either:
- **a brake** — it takes something away and can only stop, not start;
- **a bounded setting** — it changes a parameter within limits the code enforces.

None of them touches code, keys, members, the delay or build approvals.

| Contract | Owner method | What it does | Why the owner has it |
|---|---|---|---|
| DAO | `remove_approved_measurements`, `clear_all_approved_measurements` | Revoke keystore builds | The fast brake on a bad build: no keystore of it registers again until the DAO approves a build |
| DAO | `reject_registration` | Reject a keystore registration still waiting for votes | Stops a suspicious instance at once. It installs nothing and approves nothing |
| DAO | `remove_stale_proposals` | Delete registrations pending for more than 48 hours | Cleanup of instances that stopped waiting |
| DAO | `cancel` | Cancel a pending or approved proposal | A brake on a mistaken proposal. It cannot cancel a proposal that replaces an owner, a governance account or an operator — the owner cannot keep itself in place |
| DAO, register | `update_collateral` | Store Intel's TDX reference data (at most 128 KiB per slot) | Intel republishes it about monthly, and every registration verifies against it |
| Register | `remove_approved_measurements`, `clear_all_approved_measurements` | Revoke worker builds | The fast brake on a bad worker build |
| Register | `remove_worker_keys` | Remove worker keys | Retires keys of stopped workers |
| Main | `set_paused` | Pause new requests, projects and policy changes | An emergency stop. While paused, users can still freeze their wallets, and refunds and withdrawals keep working |
| Main | `set_pricing`, `set_subscription_plans`, `set_project_pricing`, `remove_project_pricing` | Prices of execution and of plans | Prices follow costs and the market |
| Main | `set_event_metadata` | The name and version stamped on events (at most 64 bytes each) | Lets indexers tell deployments apart |
| Main | `emergency_cancel_execution`, `cancel_pending_requests`, `clear_all_pending_requests` | Cancel pending requests | Each pays the request's money back in full to its payer and sender |
| Main | `withdraw_platform_near` | Withdraw NEAR fees the platform collected | Bounded by the fees collected: it cannot reach users' deposits |
| Main | `withdraw_platform_token` | Withdraw the platform's stablecoin revenue | Payment-key usage is settled off chain, so the platform's share is withdrawn by the owner |

**Replacing the owner.** The DAO replaces the owner of any contract with one proposal, and the
owner cannot cancel it. A lost or compromised owner key is a 72-hour problem, not a permanent one.

## The worker operator
`outlayer.near` accepts execution results only from `worker.outlayer.near`. That account holds no
full-access key, only the attested workers' keys described above. Which builds may run there is
the DAO's decision.

## Verifying it yourself
- **Code.** `near contract view-account-summary <account>` shows the code hash; a reproducible
  build of the release (`cargo near build reproducible-wasm`) gives the same sha256.
- **Keys.** `list-keys` shows only function-call keys.
- **Governance.** `get_governance` on `outlayer.near` and `worker.outlayer.near` returns
  `dao.outlayer.near`.
- **Members and delay.** On the DAO: `get_dao_members`, `get_gov_delay_sec`, `get_config`.
- **Proposals.** `get_gov_proposals` on the DAO lists every proposal with its votes, its delay and
  its outcome.
