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
it after the delay (72 h on mainnet, 0 on testnet).

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

```bash
(cd keystore-dao-contract && cargo near build reproducible-wasm)
```

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
cp keystore-dao-contract/target/near/keystore_dao_contract.wasm ~/dao-release/
shasum -a 256 ~/dao-release/keystore_dao_contract.wasm      # the hex from step 2
```

## 4. Upgrade

```bash
scripts/dao_upgrade.sh --network testnet --target dao --wasm ~/dao-release/keystore_dao_contract.wasm
```

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

## 6. Check

```bash
near account view-account-summary dao.outlayer.testnet network-config testnet now     # code hash = the bs58 of step 2
near contract call-function as-read-only dao.outlayer.testnet gov_health json-args '{}' network-config testnet now
near contract call-function as-read-only outlayer.testnet get_storage_version json-args '{}' network-config testnet now   # main contract: the release's version
```

## If it fails

The deploy, the new code's `migrate()` and `gov_health()` are one atomic batch: when any of them
fails, the old code stays. The proposal is `Executed` all the same and its blob is gone, so fix
the release and start again from step 1.

The same steps as plain near-cli commands, without the script:
[README.md](README.md#deploying-a-release-through-the-dao).
