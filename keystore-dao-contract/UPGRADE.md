# Upgrading a contract through the DAO

How to build a release of one of the three governed contracts and put it on chain. The same
steps for all of them:

| Contract | `--target` | Directory | Wasm |
|---|---|---|---|
| Keystore DAO (`dao.outlayer.<net>`) | `dao` | `keystore-dao-contract/` | `keystore_dao_contract.wasm` |
| Main (`outlayer.<net>`) | `main` | `contract/` | `outlayer_contract.wasm` |
| Register (`worker.outlayer.<net>`) | `worker` | `register-contract/` | `register_contract.wasm` |

No account holds a key that can deploy code. A release reaches a contract only as an `Upgrade`
proposal that names the sha256 of its wasm; members vote on that hash and one of them executes
it after the delay (72 h on mainnet by default; `get_gov_delay_sec` tells the delay in force —
600 s on testnet since 2026-11-17).

## 1. A clean committed tree

The reproducible build takes the committed state only, and records the commit in the wasm's
metadata, so every commit gives its own hash.

```bash
git status --short          # must print nothing
git push                    # the commit must be on GitHub for others to rebuild it
```

## 2. Build

Docker must be running: the build runs in the image pinned in the contract's `Cargo.toml`
(`[package.metadata.near.reproducible_build]`).

Build the contract you release, from the repository root:

```bash
(cd keystore-dao-contract && cargo near build reproducible-wasm)   # dao
(cd contract && cargo near build reproducible-wasm)                # main
(cd register-contract && cargo near build reproducible-wasm)       # worker
```

`build.sh` and `build-docker.sh` in these directories are local builds and give another hash: never
release from them.

It ends with the wasm's size and its sha256 in two forms:

```
- SHA-256 checksum hex : 74881643…
- SHA-256 checksum bs58: 8qtee4oH…
```

The **bs58** value is the `code_hash`: what the proposal names, and what NEAR shows for the
account once the code is deployed. The file is `<directory>/target/near/<wasm>`.

A build that stops on `can't find crate for …` in a dependency is a hiccup of the build
container: run it again.

## 3. Keep the file

`target/near/` is overwritten by the next build of that contract, a test build included. Copy
the release out and upgrade from the copy:

```bash
mkdir -p ~/dao-release

# dao
cp keystore-dao-contract/target/near/keystore_dao_contract.wasm ~/dao-release/
shasum -a 256 ~/dao-release/keystore_dao_contract.wasm      # the hex from step 2

# main
cp contract/target/near/outlayer_contract.wasm ~/dao-release/
shasum -a 256 ~/dao-release/outlayer_contract.wasm          # the hex from step 2

# worker
cp register-contract/target/near/register_contract.wasm ~/dao-release/
shasum -a 256 ~/dao-release/register_contract.wasm          # the hex from step 2
```

## 4. Upgrade

```bash
scripts/dao_upgrade.sh --network testnet --target dao    --wasm ~/dao-release/keystore_dao_contract.wasm
scripts/dao_upgrade.sh --network testnet --target main   --wasm ~/dao-release/outlayer_contract.wasm
scripts/dao_upgrade.sh --network testnet --target worker --wasm ~/dao-release/register_contract.wasm
```

On mainnet: `--network mainnet`, plus `--member <your>.near` when the proposer is not `zavodil.near`.

The script stores the wasm in the DAO as a blob, proposes `Upgrade{target, code_hash, migrate}`,
collects the votes, executes the proposal and checks that the account runs the hash. Run it again
at any time: it finds the open proposal and moves it on, and never proposes twice.

- `--migrate` — only for a release that changes the contract's state layout: the new code's
  `migrate()` runs in the same batch as the deploy. A release that keeps the layout goes without
  it.
- `--member <account>` — the member who proposes (default `zavodil.<net>`); `--storer <account>` —
  the member who stores the blob, if another.
- **The blob's deposit** is its storage: 0.00001 NEAR per byte (about 7.3 NEAR for 731 KB),
  attached by the storer and returned when the upgrade executes.
- **Who signs.** On testnet every step is sent, signed with the members' keys found in the local
  legacy keychain (`~/.near-credentials/testnet/`). With `DAO_CHAIN=print` in front of the
  command nothing is sent: the ready `propose`, `vote` (one per member) and `execute` commands are
  printed instead. On mainnet it always prints: members sign on their own machines.

On mainnet the proposal becomes executable 72 hours after the vote that approved it; run the
script again then. It must be executed within 7 days after that, or it expires.

## 5. What the other members do before they vote

Rebuild the same commit (steps 1–2) and compare the bs58 hash with the proposal and with the
stored blob:

```bash
near contract call-function as-read-only dao.outlayer.near get_gov_proposal json-args '{"proposal_id":<id>}' network-config mainnet now
near contract call-function as-read-only dao.outlayer.near get_blob json-args '{"hash":"<code_hash>"}' network-config mainnet now
```

A hash nobody else can rebuild is a reason to vote against.

### The code on an account, rebuilt from its commit

The hash covers the commit: the build writes the repository and the commit into the wasm
(NEP-330), so two commits give two hashes even when the contract's source is the same. Build the
commit the code names, never your own `HEAD`.

1. The commit the account's code was built from — its `source_code_snapshot` (`…?rev=<commit>`):

   ```bash
   near contract call-function as-read-only dao.outlayer.testnet contract_source_metadata json-args '{}' network-config testnet now
   ```

2. Build that commit in a separate worktree, which leaves your checkout as it is:

   ```bash
   git fetch origin
   git worktree add --detach ~/check-build <commit>   # a NEW folder with that commit; refuses a folder that exists
   (cd ~/check-build/keystore-dao-contract && cargo near build reproducible-wasm)   # dao
   (cd ~/check-build/contract && cargo near build reproducible-wasm)                # main
   (cd ~/check-build/register-contract && cargo near build reproducible-wasm)       # worker
   git worktree remove --force ~/check-build          # deletes that folder only; --force for the build's target/
   ```

   Your own checkout, its branches and uncommitted changes are not touched: `worktree remove`
   refuses the main working tree, and a path that is not a worktree.

3. Compare. near-cli shows the account's code as the **hex** sha256, the build prints both forms:

   ```bash
   near account view-account-summary dao.outlayer.testnet network-config testnet now   # "Contract (SHA-256 checksum hex)"
   ```

   The build's `SHA-256 checksum hex` equals it: the code on chain is that commit. A difference
   means another commit, or a build not from that commit's clean tree.

Example, 2026-11-17: `dao.outlayer.testnet` names `b4d277b`; its build gives hex
`57f533f1aa202a53…` (bs58 `6vML3jVt…`), the hex near-cli shows for the account. The same source
built at the next commits gives `6P3UWC79…` (`9133e0c`) and `4yCoCTYz…` (`ee2746d`).

## 6. Check

```bash
# dao
near account view-account-summary dao.outlayer.testnet network-config testnet now     # its hex = the hex of step 2
near contract call-function as-read-only dao.outlayer.testnet gov_health json-args '{}' network-config testnet now

# main
near account view-account-summary outlayer.testnet network-config testnet now         # its hex = the hex of step 2
near contract call-function as-read-only outlayer.testnet gov_health json-args '{}' network-config testnet now
near contract call-function as-read-only outlayer.testnet get_storage_version json-args '{}' network-config testnet now   # the release's version

# worker
near account view-account-summary worker.outlayer.testnet network-config testnet now  # its hex = the hex of step 2
near contract call-function as-read-only worker.outlayer.testnet gov_health json-args '{}' network-config testnet now
```

On mainnet: `.near` accounts and `network-config mainnet`.

## Order: a DAO release that changes how keystores register

A keystore registers through the DAO, so a DAO release and a keystore release that change
registration go in one order, and nothing in the code bridges a wrong one:

1. **The DAO first**, steps 1–6. Running keystores keep their keys and keep serving.
2. **The build of the new keystore, by vote**: `ApproveCompose` for its release and, for a guest
   OS the DAO has not approved yet, `ApproveOsImage`. `scripts/deploy_tdx.sh keystore` reads both
   from a deployed CVM and proposes them; on mainnet each waits out the 72 h delay.
3. **Then the keystores**, one by one: `deploy_tdx.sh keystore …`, then `--resume` once the build
   is approved. Each instance takes one vote, for its key.

Between 1 and 3 no keystore of the previous release can register again: a restart of one stays
down until it is replaced by the new release. Do not restart keystores in that window.

## If it fails

The deploy, the new code's `migrate()` and `gov_health()` are one atomic batch: when any of them
fails, the old code stays. The proposal is `Executed` all the same and its blob is gone, so fix
the release and start again from step 1.

The same steps as plain near-cli commands, without the script:
[README.md](README.md#deploying-a-release-through-the-dao).
