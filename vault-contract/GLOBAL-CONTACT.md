# Vault contract — global-contract deploy

The vault WASM is deployed on chain as a [Global Contract by hash](https://docs.near.org/protocol/global-contracts) and every customer's vault account references it with `Action::UseGlobalContract`. The per-vault deploy transaction then carries a 32-byte SHA-256 instead of the ~190 KB WASM, which keeps it small enough for browser-wallet URL-redirect signing (e.g. MyNearWallet).

## One-time deploy (per network, per WASM version)

Anyone with enough NEAR to pay the storage can deploy; the global identifier is the WASM's SHA-256, whoever paid. Deploying makes the code available; customers' clients use it only once the keystore DAO has approved the same hash.

### Testnet
```bash
near contract deploy-as-global use-file \
  res/vault_contract.wasm \
  as-global-hash \
  outlayer.testnet \
  network-config testnet sign-with-keychain send

near contract call-function as-transaction \
  dao.outlayer.testnet approve_vault_version \
  json-args '{"hash":"<base58 sha256>","label":"<label>","audit_url":null}' \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  sign-as <dao-member>.testnet network-config testnet sign-with-keychain send
```

### Mainnet
```bash
near contract deploy-as-global use-file \
  res/vault_contract.wasm \
  as-global-hash \
  outlayer.near \
  network-config mainnet sign-with-keychain send

near contract call-function as-transaction \
  dao.outlayer.near approve_vault_version \
  json-args '{"hash":"<base58 sha256>","label":"<label>","audit_url":null}' \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  sign-as <dao-member>.near network-config mainnet sign-with-keychain send
```

Replace `outlayer.testnet` / `outlayer.near` with whichever account pays storage. A mainnet deploy must use a build WITHOUT `--features test-timing` (see [README.md](./README.md#building)).

`approve_vault_version` executes once `approval_threshold` (>50%) DAO members have called it with the same `label` and `audit_url`; each call returns the vote count so far. With the DAO at one member, one call approves.

Check what is approved:

```bash
near contract call-function as-read-only dao.outlayer.near \
  list_approved_vault_versions json-args '{}' network-config mainnet now
```

Check the code is available as a global contract:

```bash
HASH=<base58 sha256 of res/vault_contract.wasm>
curl -sS -X POST https://rpc.mainnet.fastnear.com -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"id\":\"q\",\"method\":\"query\",
  \"params\":{\"request_type\":\"view_global_contract_code\",
              \"finality\":\"final\",
              \"code_hash\":\"$HASH\"}}"
```

It returns `{ "result": { "code_base64": "...", "hash": "...", "block_height": ..., "block_hash": "..." }, ... }`.

## The vault deploy transaction

`buildVaultDeployActions` in the dashboard's `lib/vault.ts` and `atomic_deploy_vault` in `outlayer-cli/src/near.rs` build the same five-action atomic deploy, signed by the parent account:

1. `CreateAccount` — the vault sub-account.
2. `Transfer` — 1 NEAR: storage plus a standing reserve for the vault's outbound `request_master` gas prepayments.
3. **`UseGlobalContract { CodeHash: <32 bytes> }`** — references the WASM already on chain.
4. `FunctionCall { method: "new", args: { parent, keystore_dao, mpc_contract, initial_tee_pubkey, initial_exit_window } }` — the constructor.
5. `AddKey` — the TEE-derived function-call key (same pubkey as `initial_tee_pubkey`), scoped to `(receiver=<vault>, methods=["request_master"])`, unlimited allowance.

## Updating the WASM

1. Edit `vault-contract/src/lib.rs`. Rebuild with `./build.sh`, or `./build-docker.sh` for the reproducible hash.
2. Deploy the new WASM as a global contract (`near contract deploy-as-global use-file ... as-global-hash`). Each global hash costs storage separately; earlier versions stay referenceable.
3. Approve the new hash on the DAO (`approve_vault_version`, quorum-gated as above). Optionally `deprecate_vault_version` the previous one (single DAO member; existing vaults keep working).
4. `outlayer vault init` and the dashboard's Create Vault view-call `keystore_dao.list_approved_vault_versions()` and use the most recent non-deprecated entry — no client rebuild needed.

Existing vaults keep the code they were deployed with: the `UseGlobalContract { CodeHash }` reference is permanent and the contract cannot redeploy itself. A customer moves to a new version by deploying a new vault. `revoke_vault_version` (quorum-gated) removes a hash from the approved set: a vault on it can no longer pass `/customer/sign-verification`, but a vault already in `verified_vaults` keeps being served until the DAO bans it (`ban_vault`).

## Caveats

- The payer of a global contract by hash pays storage permanently; a global contract cannot be deleted. Use the canonical operator account.
- Anyone can deploy a WASM as a global contract. That is harmless: hash-addressed deploys are content-addressed, and only DAO-approved hashes are used.
- The `as-global-account-id` mode is mutable (the deployer account can replace the code). Vaults use `as-global-hash` so the code they reference cannot change.
