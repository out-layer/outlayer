# Governance

OutLayer's three on-chain contracts are governed by a DAO. No account holds a key that can
change their code. The DAO members decide together, and every change of the rules, of the code
or of the software that may hold the master secret waits out a public delay.
An operations owner runs day-to-day settings. It can apply the brakes and adjust parameters, but
it cannot change what the contracts are, and the DAO can replace it at any time.

| Contract | Account (mainnet) | Role |
|---|---|---|
| Keystore DAO | `dao.outlayer.near` | The governance root: members, proposals, the keystore builds allowed to obtain the master secret |
| Main | `outlayer.near` | Execution requests, payments, projects, secrets, wallet policies |
| Register | `worker.outlayer.near` | The TEE workers: which builds may run, and their keys |

## No full-access keys

None of the three accounts has a full-access key. Nobody can deploy code to them, add a key, or
sign arbitrary transactions as them.

### Function-call keys

`list-keys` on these accounts still shows keys: function-call keys. Each is a service key for one
narrow job. It signs calls only to the methods listed on it, on one named contract; it cannot
deploy code, add or remove keys, or transfer NEAR, and its allowance pays only for the gas of
those calls. A contract installs each of them, never a person:

- **Workers on `worker.outlayer.near`.** Each worker's key is added only after its Intel TDX
  attestation is verified on chain against a build the DAO approved. The key may call only the
  four methods a worker needs on `outlayer.near`: delivering results and settling payments. Its
  gas allowance is 10 NEAR.
- **Keystores on `dao.outlayer.near`.** Each keystore's key is added only by a DAO vote on its
  verified attestation, and only for a build the DAO approved. It may call only `request_key`
  (obtain the master secret through NEAR MPC), `mark_vault_verified` and `ban_vault`.

The set follows the running fleet: the keys on an account are those of the instances running
now. A redeployed worker or keystore registers a new key, and the old one is removed as it is
rotated out: a worker's by `remove_worker_keys`, a keystore's by a DAO vote
(`propose_revoke_keystore_keys`).

Read the keys yourself:

```bash
near account list-keys dao.outlayer.near network-config mainnet now
near account list-keys outlayer.near network-config mainnet now
near account list-keys worker.outlayer.near network-config mainnet now
```

## The DAO

- **Members.** Three accounts. Any two of three approve a proposal (`approval_threshold = members / 2 + 1`, recomputed when membership changes).
  `get_dao_members` on `dao.outlayer.near` lists them.
- **Delay.** An approved proposal executes no earlier than 24 hours after the vote that approved
  it. Anyone watching the chain has a day to see what is coming. One vote has no delay:
  admitting an instance of a keystore whose software the DAO already approved through such a
  proposal.
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
| Approve the software a keystore may run (the builds that may obtain the master secret) | `ApproveCompose`: the hash of the release's exact software, rebuilt by anyone from the published compose. `ApproveOsImage`: the guest OS it runs under. Both wait out the delay |
| Admit one keystore instance | A vote on its registration. The contract verifies the instance's Intel TDX attestation, checks that it runs an approved OS and an approved release, and records which instance it is. The vote names the key it installs, so it cannot land on another instance's registration. Every instance takes its own vote; the build is checked again when the vote reaches quorum |
| Approve a worker build | A `Call` to `add_approved_measurements` on the register |
| Replace the operations owner of any contract | `SetOwner`, or a `Call` to `set_owner` |
| Replace a contract's governance account or the main contract's operator | A `Call` to `set_governance` / `set_operator` |
| Change the stablecoin the main contract accepts | A `Call` to `set_payment_token_contract` |
| Move a balance held by the main contract (a rescue) | A `Call` to `gov_transfer` |
| Revoke keystore keys | `propose_revoke_keystore_keys`, decided by the members' vote |

A `Call` proposal can reach only a contract the DAO governs, and never the DAO itself or the MPC
contract. Code changes only as an `Upgrade`, by its hash.

### What any single member can do
Each of these is a narrow switch, not a change of rules:
- Flag a customer vault as banned or unbanned.
- Mark an approved vault version deprecated.
- Declare or revoke cessation of operations, which opens the vaults' own recovery path for their customers.

## The operations owner

`owner.outlayer.near` runs the parts that must happen quickly or routinely. Waiting a day for a
vote would hurt users there: stopping a bad build at once, refreshing Intel's reference data
every month, setting prices.

Every owner power is either:
- **a brake** — it takes something away and can only stop, not start;
- **a bounded setting** — it changes a parameter within limits the code enforces.

None of them touches code, keys, members, the delay or build approvals.

| Contract | Owner method | What it does | Why the owner has it |
|---|---|---|---|
| DAO | `remove_approved_compose`, `remove_approved_os_image` | Revoke keystore builds | The fast brake on a bad build: no keystore of it registers again until the DAO approves a build |
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
owner cannot cancel it. A lost or compromised owner key is a 24-hour problem, not a permanent one.

## The worker operator
`outlayer.near` accepts execution results only from `worker.outlayer.near`. That account holds no
full-access key, only the attested workers' keys described above. Which builds may run there is
the DAO's decision.

## Verifying it yourself
- **Code.** `near account view-account-summary <account> network-config mainnet now` shows the code hash; a reproducible
  build of the release (`cargo near build reproducible-wasm`) gives the same sha256.
- **Keys.** `list-keys` shows only function-call keys.
- **Governance.** `get_governance` on `outlayer.near` and `worker.outlayer.near` returns
  `dao.outlayer.near`.
- **Members and delay.** On the DAO: `get_dao_members`, `get_gov_delay_sec`, `get_config`.
- **Proposals.** `get_gov_proposals` on the DAO lists every proposal with its votes, its delay and
  its outcome.
