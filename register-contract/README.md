# Register Contract — TEE worker key registration

The NEAR contract that admits an execution worker's key only after verifying an Intel TDX
quote for it. A registered key is added as a function-call access key to the contract's own
account, and that account is the operator the main OutLayer contract accepts execution
results from.

| Network | Contract (= operator account) | Owner | Init worker account | Main contract |
|---|---|---|---|---|
| mainnet | `worker.outlayer.near` | `owner.outlayer.near` | `init-worker.outlayer.near` | `outlayer.near` |
| testnet | `worker.outlayer.testnet` | `owner.outlayer.testnet` | `init-worker.outlayer.testnet` | `outlayer.testnet` |

Governance is the keystore DAO (`dao.outlayer.<net>`). `get_init_worker_account`,
`get_owner` and `get_governance` return the roles.

Source: `src/lib.rs` (contract), `src/collateral.rs` (Intel collateral parsing, taken from
the NEAR MPC node; see `NOTICE`), `src/migration.rs` (state migration). The `attestation/`
and `mpc-primitives/` directories are not part of the contract build.

## Roles

- **Governance (the DAO, by vote and delay):** approves worker builds
  (`add_approved_measurements`, through a DAO `Call` proposal), replaces the owner
  (`set_owner`) and itself (`set_governance`), and upgrades this contract
  (`upgrade` / `upgrade_and_migrate`). An approved build registers keys that open keystore
  sessions, so approving one is never an owner's decision.
- **Owner (ops):** revokes builds (`remove_approved_measurements`,
  `clear_all_approved_measurements`), removes worker keys, keeps the Intel collateral
  current. Governance can revoke and remove keys too.
- **The worker keys** on this account are the operator the main contract accepts results
  from (`predecessor == operator_id`). The coordinator and keystore admit a worker session
  only for a function-call key on this account.

## How a worker registers

1. The worker generates a keypair (`WORKER_KEY_TYPE`: ed25519 or ml-dsa-65) inside the CVM
   and writes it to `~/.near-credentials/worker-keypair.json` in its container. A restart
   that keeps the file reuses the key.
2. It requests a TDX quote from dstack with `report_data[0..32]` = the raw ed25519 public
   key, or SHA-256 of the ml-dsa-65 public key.
3. It reads the five measurements from its own quote and polls `is_measurements_approved`
   (every 5 s, up to ~8 minutes) before spending gas.
4. The init worker account calls `register_worker_key(public_key, tdx_quote_hex)` with
   300 TGas and no deposit. Only that account may call it. The contract:
   - picks the cached collateral whose FMSPC matches the quote (no collateral may be passed
     in the call) and verifies the quote with `dcap-qvl` 0.3.11 at the block's timestamp;
   - refuses any TCB status other than `UpToDate`, and any quote with outstanding Intel
     security advisories;
   - extracts MRTD and RTMR0–3 and requires the five together to match one approved entry;
   - recomputes the `report_data` binding from `public_key` and requires it to equal the
     quote's;
   - adds `public_key` to its own account: function-call key, receiver = the main contract,
     methods `resolve_execution`, `submit_execution_output_and_resolve`, `resume_topup`,
     `resume_delete_payment_key`, allowance 10 NEAR.
5. A worker whose key is already on the account skips registration.

The contract stores no record of registered keys or their quotes: the access-key list of
the account is the registry, and each registration's quote and measurements are in its
transaction (the measurements also in its logs).

A key stays valid until the owner or governance removes it. Keys of decommissioned workers are retired
with `scripts/revoke_old_worker_keys.sh <network>`: it keeps the keys the coordinator has
recorded for running workers (each confirmed on chain) and prints, or with `--send`
sends, `remove_worker_keys` for the rest.

## Methods

### Init and migration

- `new(owner_id, init_worker_account, outlayer_contract_id, governance_id)`
- `migrate(governance_id)` — `#[private]`; adds governance to the previous state layout.
  Every version deployed through governance after this one has a `migrate()` without
  arguments.

### Governance

- `add_approved_measurements(measurements, clear_others?)` — `measurements` is
  `{mrtd, rtmr0, rtmr1, rtmr2, rtmr3}`, each exactly 96 hex characters. `clear_others: true`
  drops every other entry first. Adding an existing entry is a no-op.
- `set_owner(new_owner_id)`, `set_governance(governance_id)` — the same names and arguments as
  on the main contract
- `upgrade()` / `upgrade_and_migrate()` — the wasm as the raw input of the call (not JSON).
  One atomic batch on this account: deploy [+ `migrate()`] + `gov_health()`; a failing step
  leaves the old code. Every version keeps these three methods.

### Owner or governance

- `remove_approved_measurements(measurements)`, `clear_all_approved_measurements()`
- `remove_worker_keys(public_keys)` — schedules one `DeleteKey` per key, each independent,
  so a missing key does not stop the others. The account holds only workers' function-call
  keys, so the worst a removal does is stop a worker.

### Owner

- `update_collateral(collateral, index)` — see [Collateral](#collateral).

### Init worker account

- `register_worker_key(public_key, tdx_quote_hex) -> Promise`

### Views

- `get_approved_measurements()`, `is_measurements_approved(measurements)`
- `get_collateral()` (slot 0), `get_collaterals()` (all slots)
- `get_init_worker_account()`, `get_owner()`, `get_governance()`, `gov_health()`

```bash
near contract call-function as-read-only worker.outlayer.near get_approved_measurements \
  json-args '{}' network-config mainnet now
near account list-keys worker.outlayer.near network-config mainnet now
```

## Collateral

Verifying a quote needs Intel's collateral for the platform that produced it: TCB info, QE
identity, their signatures and issuer chains, and the PCK and root CA revocation lists. The
contract holds it as `QuoteCollateralV3` JSON, in at most two slots, one per platform FMSPC;
a registration is checked against the slot whose FMSPC matches the quote. The keystore DAO
contract keeps collateral the same way.

- `update_collateral(collateral, index)` (owner) takes the JSON **as a string** and a slot
  index (`0` or `1`). A slot is replaced in place, a new slot may only be the next index, and
  the other slot is untouched. The contract stores it as given; a registration verifies the
  quote against it.
- The TCB info and QE identity each carry an issue date and a next-update date, and
  `dcap-qvl` refuses a quote verified outside that window. Collateral must be replaced before
  its next-update date, or every registration on that platform fails.
- `scripts/update_collateral.sh <collateral.json> <index> [network] [contract]` sends the
  update as the owner (pass `dao.outlayer.<net>` as the contract for the DAO), and documents
  how the JSON is generated on a node from its local PCCS with `dcap-qvl`. It removes
  `pck_certificate_chain` before sending: that field is one machine's PCK chain, and
  `dcap-qvl` prefers it over the chain inside the quote, which would make every other node of
  the same FMSPC fail.
- The contract keeps only the newest collateral per slot, and Intel's PCS serves only the
  current one. After each update the script asks the coordinator to archive the version
  (`POST /admin/collateral/check`); the archive is served at
  `GET https://api.outlayer.ai/public/collateral?fmspc=<fmspc>&at=<time>`, so an old
  attestation can still be verified. The body is Intel-signed, so serving it gives OutLayer
  no influence over a verdict. Remaining validity per platform is reported by the
  coordinator's `GET /admin/collateral/status`.

## Deploying a worker build

From an operator machine:

```bash
./scripts/deploy_tdx.sh worker <testnet|mainnet> --version <ver> --node <ssh-target>
```

It deploys the CVM on the node from a pinned, attested release image, reads the new
measurements and proposes them to the DAO as a `Call` to `add_approved_measurements` (or
executes the open proposal once it is approved and its delay has passed; `GOV_MEMBER` signs),
and waits for the worker to register itself. When the proposal still waits for votes or for
the delay, it prints the remaining steps and stops; a worker that gave up waiting is
restarted after the execution. Measurements are approved once per (network, version). The
node-side files are under `deploy/self-hosted-tdx`.

Upgrading this contract: `scripts/dao_upgrade.sh --target worker --wasm <file>`.

## Build and test

```bash
./build-docker.sh   # cargo near build in sourcescan/cargo-near:0.22.0-rust-1.97.1
./build.sh          # local cargo near build; needs an LLVM clang/llvm-ar for the ring crate
cargo test
```

Both write `res/register_contract.wasm` and are for development. The release build is
reproducible, from a clean committed tree, in the image pinned in `Cargo.toml`
(`[package.metadata.near.reproducible_build]`):

```bash
cargo near build reproducible-wasm   # target/near/register_contract.wasm
```

Its sha256 is the `code_hash` a DAO upgrade proposal names.

`cargo test` needs near-sdk's `unit-testing` feature as a dev-dependency, which the committed
`Cargo.lock` does not resolve; run the tests on a copy with that dev-dependency and the DAO's
lock file.

## License

Apache-2.0. `src/collateral.rs` is derived from [near/mpc](https://github.com/near/mpc)
under the MIT License; see `NOTICE`.
