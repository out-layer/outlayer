# OutLayer Smart Contract

NEAR smart contract for off-chain WASM execution using yield/resume mechanism.

- Testnet: `outlayer.testnet`
- Mainnet: `outlayer.near`

## Features

- **Yield/Resume Mechanism**: Uses `promise_yield_create` to pause execution
- **Off-chain Computation**: Execute arbitrary WASM code off-chain
- **Resource Limits**: Configurable limits for instructions, memory, and time
- **Dynamic Pricing**: Cost calculated based on actual resource usage
- **Stale Request Cancellation**: Users can cancel requests after timeout
- **Admin Controls**: Owner can manage operators, pricing, and pause contract
- **Secret Management**: Encrypted secrets support via keystore worker integration

## Contract API

### User Functions

#### `request_execution`
Request off-chain execution of WASM code.

**Basic execution (no secrets):**
```bash
near call outlayer.testnet request_execution '{
  "code_source": {
    "repo": "https://github.com/user/project",
    "commit": "abc123",
    "build_target": "wasm32-wasi"
  },
  "resource_limits": {
    "max_instructions": 1000000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  },
  "input_data": "{\"key\": \"value\"}"  
}' --accountId user.testnet --deposit 0.01
```

**With encrypted secrets (e.g., API keys):**
```bash
# 1. Get keystore public key
near contract call-function as-read-only outlayer.testnet get_keystore_pubkey json-args {} network-config testnet now

# 2. Encrypt your secrets with the public key (use keystore encryption library)
# encrypted_data = encrypt_for_keystore(pubkey, "OPENAI_API_KEY=sk-...")

# 3. Call with encrypted secrets
near call outlayer.testnet request_execution '{
  "code_source": {...},
  "resource_limits": {...},
  "input_data": "{...}",
  "secrets_ref": {
    "profile": "default",
    "account_id": "dev.testnet"
  }
}' --accountId user.testnet --deposit 0.1
```

`secrets_ref.profile` is checked at the door with the rule `store_secrets`
applies to a profile name — 1–64 bytes of letters, digits, `-` or `_` — and a
reference no row could match is refused before the request yields, naming
that rule.

#### `cancel_stale_execution`
Cancel execution request after timeout (10 minutes).

```bash
near call outlayer.testnet cancel_stale_execution '{
  "request_id": 123
}' --accountId user.testnet
```

### Operator Functions

#### `resolve_execution`
Resolve execution with results (called by worker).

**Small output (<1024 bytes):**
```bash
near call outlayer.testnet resolve_execution '{
  "request_id": 0,
  "response": {
    "success": true,
    "output": {"Text": "Hello, NEAR!"},
    "error": null,
    "resources_used": {
      "instructions": 1000000,
      "time_ms": 100
    }
  }
}' --accountId operator.testnet
```

#### `submit_execution_output_and_resolve`
Optimized single-transaction method for large outputs (>1024 bytes). Used automatically by worker.

```bash
near call outlayer.testnet submit_execution_output_and_resolve '{
  "request_id": 0,
  "output": {"Text": "Very long output..."},
  "success": true,
  "error": null,
  "resources_used": {
    "instructions": 1000000,
    "time_ms": 100,
    "compile_time_ms": null
  },
  "compilation_note": null
}' --accountId operator.testnet
```

**Note**: Worker automatically chooses between `resolve_execution` (small output) and `submit_execution_output_and_resolve` (large output) based on payload size.

### Admin Functions

#### `set_operator`
Change operator account.

```bash
near call outlayer.testnet set_operator '{
  "new_operator_id": "new-operator.testnet"
}' --accountId owner.testnet
```

#### `set_pricing`
Update pricing parameters.

```bash
near call outlayer.testnet set_pricing '{
  "base_fee": "10000000000000000000000",
  "per_instruction_fee": "1000000000000000",
  "per_mb_fee": "100000000000000000000",
  "per_second_fee": "1000000000000000000000"
}' --accountId owner.testnet
```

#### `set_paused`
Pause/unpause contract.

```bash
near call outlayer.testnet set_paused '{
  "paused": true
}' --accountId owner.testnet
```

### View Functions

#### `get_request`
Get execution request by ID.

```bash
near view outlayer.testnet get_request '{
  "request_id": 123
}'
```

#### `get_stats`
Get contract statistics.

```bash
near contract call-function as-read-only outlayer.testnet get_stats json-args {} network-config testnet now
```

#### `get_pricing`
Get current pricing.

```bash
near view outlayer.testnet get_pricing '{}'
```

#### `get_config`
Get contract configuration.

```bash
near view outlayer.testnet get_config '{}'
```

### Project Functions

A project is `{owner}/{name}`: the name is 1–64 bytes of ASCII letters,
digits, `-` or `_` (a Cyrillic `а` in `polymаrket` is not a name — it would
read as the real one). `create_project`, `add_version`, `set_active_version`,
`remove_version` and `delete_project` are the owner's; see
[PROJECT.md](../PROJECT.md) for their arguments.

#### `accept_project_transfer`

A project moves only onto an acceptance given by the account that will own
it, for exactly that project and that owner. Without one, `transfer_project`
is refused — so nobody can put their code under a name in another account's
namespace (`connectors.outlayer.near/<name>` before the real one exists)
without that account asking for it.

```bash
# bob agrees to take alice.testnet/my-app. The deposit pays for the record and
# comes back when it is consumed or revoked; estimate_transfer_acceptance_cost
# quotes it (about 0.002 NEAR).
near call outlayer.testnet accept_project_transfer '{"from": "alice.testnet", "name": "my-app"}' --accountId bob.testnet --deposit 0.01
```

The project need not exist yet. Refused when `bob.testnet/my-app` already
exists, or when bob has already accepted that project. An acceptance pins the
name and the owner, not the code: alice keeps every right over the project
until the transfer lands, and bob checks what arrived with `get_version`
afterwards. Emits `system_event` `ProjectTransferAccepted { new_owner, from, name }`.

```bash
# The acceptance bob holds, as the deposit held for it; null when there is none.
near view outlayer.testnet get_project_transfer_acceptance '{"new_owner": "bob.testnet", "from": "alice.testnet", "name": "my-app"}'
```

#### `revoke_project_transfer`

```bash
near call outlayer.testnet revoke_project_transfer '{"from": "alice.testnet", "name": "my-app"}' --accountId bob.testnet
```

Only the account that gave the acceptance can take it back; the record's
deposit returns to it. Emits `ProjectTransferRevoked { new_owner, from, name }`.

#### `transfer_project`

```bash
near call outlayer.testnet transfer_project '{"project_name": "my-app", "new_owner": "bob.testnet"}' --accountId alice.testnet
```

Renames `alice.testnet/my-app` to `bob.testnet/my-app`; the uuid, the versions
and the storage stay. Requires bob's acceptance, consumes it and returns its
deposit to bob. A priced project does not move: pricing is the contract
owner's, so the OutLayer operator unprices it (`remove_project_pricing`)
first. Emits `ProjectTransferred`.

#### `estimate_transfer_acceptance_cost`

```bash
near view outlayer.testnet estimate_transfer_acceptance_cost '{"new_owner": "bob.testnet", "from": "alice.testnet", "name": "my-app"}'
```

The deposit `accept_project_transfer` will charge, in yoctoNEAR.

### Wallet Policy Functions

A custody wallet's policy is stored here encrypted; only the keystore decrypts
it. The account that sends `store_wallet_policy` becomes its controller.

#### `store_wallet_policy`
Create or update a policy. Needs a signature by the wallet's own key over
`store_wallet_policy:v1:{wallet_pubkey}:{len}:{encrypted_data}:{caller}` (the
keystore makes it) and a storage deposit (`estimate_wallet_policy_cost`).

`storage_refund_to` (optional) names who the storage deposit goes back to —
for a sponsor that pays it while the owner signs. It is set only when the
policy is CREATED: an update that names it fails. From then on every refund
goes to it — the excess of the creating call, the difference when an update
shrinks the policy, and the whole deposit on `delete_wallet_policy`. The owner
keeps every power over the policy itself (update, freeze, delete); it cannot
change where the deposit goes. That includes the excess of the owner's own
attachment on an update: attach exactly `estimate_wallet_policy_cost`, or the
rest goes to the beneficiary. Without the argument, refunds go to the caller,
as before. The argument is covered by the owner's transaction signature, so a
NEP-366 relayer cannot change it.

```bash
near contract call-function as-transaction outlayer.testnet store_wallet_policy json-args '{
  "wallet_pubkey": "ed25519:<hex>", "encrypted_data": "<base64>",
  "wallet_signature": "<hex>", "storage_refund_to": "sponsor.testnet"
}' prepaid-gas '100.0 Tgas' attached-deposit '0.05 NEAR' sign-as owner.testnet network-config testnet sign-with-keychain send
```

#### `set_storage_refund_to`
Hand the refunds on: `{"item": {"WalletPolicy": {"wallet_pubkey": "ed25519:<hex>"}}, "storage_refund_to": "other.testnet"}`.
Only the current beneficiary can call it — to pass the deposit to another
sponsor, or to the owner to give it back. The owner cannot take it, and a
policy created without a beneficiary never gets one. No deposit is attached and
nothing is refunded: the record keeps its size. Emits `StorageRefundToChanged`.

**The beneficiary answers for its account existing.** A refund to an account
that no longer exists fails on chain and the NEAR stays with the contract; the
contract cannot check this in advance.

`StorageItem` is what a refundable deposit is held for. Today it has one
variant, `WalletPolicy { wallet_pubkey }`; a new kind of sponsored storage is a
new variant and an argument on its creating call.

#### `delete_wallet_policy`
Controller only. Returns the whole deposit to the beneficiary when one is set,
otherwise to the caller, and drops the beneficiary: a policy created again
under the key starts without one. The `WalletPolicyDeleted` event carries
`refunded_to`.

#### `freeze_wallet` / `unfreeze_wallet`
Controller only, no wallet signature: the emergency stop for a compromised
agent key.

#### Views
- `get_wallet_policy(wallet_pubkey)` → `{owner, encrypted_data, frozen, updated_at, storage_refund_to, storage_deposit}` or `null`. A sponsor checks `storage_refund_to` before it pays.
- `get_wallet_policies_by_owner(owner)` → `[{wallet_pubkey, owner, frozen, updated_at, storage_refund_to}]`.
- `has_wallet_policy(wallet_pubkey)` → `bool`.
- `estimate_wallet_policy_cost(wallet_pubkey, encrypted_data, storage_refund_to?)` → yoctoNEAR as a string; with `storage_refund_to` it includes the beneficiary's record, as the store will charge it.

### Secrets Management Functions

#### `store_secrets`
Store encrypted secrets for a repository. `profile` names the row: 1–64 bytes
of letters, digits, `-` or `_`. The same rule refuses, at `request_execution`,
a `secrets_ref` no row could match.

**Important:** Always estimate storage cost first using `estimate_storage_cost` to attach the correct deposit.

```bash
# 1. Estimate storage cost. The arguments are the slot the store will use:
# an ACCESSOR (not repo/branch), the profile, the owner, the ciphertext and the
# condition — the condition is priced too, so a large whitelist costs more.
near view outlayer.testnet estimate_storage_cost '{
  "accessor": {"Repo": {"repo": "github.com/alice/project", "branch": "main"}},
  "profile": "default",
  "owner": "alice.testnet",
  "encrypted_secrets_base64": "YWJjZGVm...",
  "access": "AllowAll",
  "vault_id": null
}'
# Output: "1500000000000000000000" (0.0015 NEAR)

# 2. Store secrets with exact deposit
near call outlayer.testnet store_secrets '{
  "repo": "github.com/alice/project",
  "branch": "main",
  "profile": "default",
  "encrypted_secrets_base64": "YWJjZGVm...",
  "access": "AllowAll"
}' --accountId alice.testnet --deposit 0.0015
```

#### `estimate_storage_cost`
Estimate the storage cost before storing secrets. Returns exact cost in yoctoNEAR.

```bash
near view outlayer.testnet estimate_storage_cost '{
  "repo": "github.com/alice/project",
  "branch": null,
  "profile": "production",
  "owner": "alice.testnet",
  "encrypted_secrets_base64": "YWJjZGVm...",
  "access": {"Whitelist": {"accounts": ["alice.testnet", "bob.testnet"]}}
}'
```

**Pricing factors:**
- Base overhead: 40 bytes (LookupMap entry)
- Key size: repo + branch + profile + owner (with Borsh length prefixes)
- Value size: encrypted_secrets + access condition + timestamps
- Index overhead: 64 bytes (for new secrets)
- Storage price: 0.00001 NEAR per byte

**Note:** Complex access conditions (e.g., Whitelist with many accounts) cost more than simple ones (e.g., AllowAll).

#### `get_secrets`
Retrieve secrets for a repository (called by keystore worker).

```bash
near view outlayer.testnet get_secrets '{
  "repo": "github.com/alice/project",
  "branch": "main",
  "profile": "default",
  "owner": "alice.testnet"
}'
```

#### `delete_secrets`
Delete secrets and get storage deposit refund.

```bash
near call outlayer.testnet delete_secrets '{
  "repo": "github.com/alice/project",
  "branch": "main",
  "profile": "default"
}' --accountId alice.testnet
```

#### `update_access`
Change who may read a stored secret. The condition moves and the ciphertext
stays, so no value is re-entered and a TEE-generated key is never lost. Keyed on
`(accessor, profile, caller)`: only the owner of the row can change it, and a
non-owner's call panics with `Secrets not found`. This is how an owner hands a
secret to an agent and takes it back — the agent names `{account_id: owner,
profile}` in `secrets_ref`.

Payable, because a condition is stored bytes: a `Whitelist` of two thousand
accounts occupies some fifty kilobytes whichever door it arrives through. The
row is re-priced against the new condition and the deposit already held counts
towards it, so narrowing refunds the difference, an edit that does not change
the size needs nothing, and only growth asks for more. Call
`estimate_storage_cost` with the row's existing `encrypted_secrets_base64` and
the new condition to learn the figure; attaching it is always sufficient, and
the excess comes back in the same transaction.

```bash
near call outlayer.testnet update_access '{
  "accessor": {"Project": {"project_id": "alice.testnet/app"}},
  "profile": "default",
  "new_access": {"Logic": {"operator": "Or", "conditions": [
    {"Whitelist": {"accounts": ["alice.testnet"]}},
    {"Logic": {"operator": "And", "conditions": [
      {"Whitelist": {"accounts": ["<agent wallet account>"]}},
      {"ValidUntil": {"until_ns": "1790812800000000000"}}
    ]}}
  ]}}
}' --accountId alice.testnet --gas 30000000000000 --deposit 0.1
```

#### Access conditions
`access` (on `store_secrets` and `update_access`) is an `AccessCondition`, evaluated
by the keystore inside the TEE against the account the run is attributed to — the
transaction's SIGNER on chain (a contract that relays `request_execution` is the
predecessor and pays, but the signer is the one judged — unless the condition
says otherwise with `Predecessor`), a payment key's owner over HTTPS — never
against a name the call claims. Variants: `"AllowAll"`; `{"Whitelist": {"accounts": [...]}}` (exact match);
`{"AccountPattern": {"pattern": "..."}}` (a regex anchored to the whole id);
`{"NearBalance": {"operator": "Gte", "value": "<yocto>"}}`; `{"FtBalance": {"contract",
"operator", "value"}}`; `{"NftOwned": {"contract", "token_id"}}`; `{"DaoMember":
{"dao_contract", "role"}}`; `{"ValidUntil": {"until_ns": "<nanoseconds since the
epoch, as a string>"}}` (admits strictly before that instant); `{"WasmHash": {"hash":
"<SHA-256 of the build, 64 lowercase hex>"}}` (admits only a run of that exact build —
the keystore compares it with the hash the worker measured on the bytes it executes;
`update_access` moves a row to the next build without re-encrypting);
`{"Predecessor": {"condition": ...}}` (judges the condition it wraps on the account
that CALLED the contract — `predecessor_account_id`: the relaying contract, or the
signer on a direct call — so `And[Whitelist[me], Predecessor{Whitelist[me]}]` admits only
the owner's own direct calls and `Predecessor{Whitelist[dao]}` only calls through that
DAO; over HTTPS the payment key's owner is judged as the calling account too, so there
the wrapper adds nothing); `{"Logic": {"operator":
"And" | "Or", "conditions": [...]}}` and `{"Not": {"condition": ...}}` to combine
them. The contract stores the condition without evaluating it; the Borsh layout of
`SecretProfile.access` is the variant order, so new variants are only ever appended.

The contract stores no condition the keystore would refuse to judge, so both
`store_secrets` and `update_access` refuse one past these bounds — and
`estimate_storage_cost` quotes no such condition either:

* at most **5** leaves that can only be answered by asking the chain
  (`NearBalance`, `FtBalance`, `NftOwned`, `DaoMember`). They are asked one
  after another from inside the enclave, against contracts the row's owner
  chose, and a shared keystore waits for all of them;
* at most **16** `AccountPattern` leaves and **4096 bytes** of pattern text in
  all. A pattern's compiled size is not its text size, and the keystore
  compiles every pattern of a condition before judging a decrypt.

A whitelist is answered from the condition itself, so neither its size nor the
number of whitelist leaves is bounded — the only cost is storage, which the
row's owner pays for.

#### `list_user_secrets`
One PAGE of the secrets stored by an account. It reads storage per entry, so an
unbounded answer would eventually exceed the view's gas and fail for everyone —
omitting the paging arguments gives the first 100, not the whole set. Ask for the
next page until one comes back short.

```bash
near view outlayer.testnet list_user_secrets '{
  "account_id": "alice.testnet",
  "from_index": 0,
  "limit": 100
}'
```

`limit` is capped at 500. Both arguments may be omitted.

#### Payment key nonces
A payment key is a secret under the `System: PaymentKey` accessor whose profile
is its nonce. A nonce is handed out to an owner once: `store_secrets` refuses a
payment key at or below the owner's floor — the highest nonce the contract has
seen them create or delete — with "has already been used". The coordinator
keeps a deleted key's row under `(owner, nonce)`, and a new key there would
bring it back with the old balance and grants.

- `get_next_payment_key_nonce({account_id})` — the lowest nonce a new key may
  take: one above both the live keys and the floor.
- `get_payment_key_nonce_floor({account_id})` — the floor; 0 when none is
  recorded.

The floor is raised when a key is created and when one is deleted, so it holds
every nonce the contract has seen come or go; a key older than the owner's
floor entry is recorded when it is deleted. Its entry is
paid once, by the owner's first key (included in `estimate_storage_cost`), and
is not refunded: it outlives every key. `delete_payment_key` refunds the key's
storage deposit; its unspent balance is forfeited.

## Events

### `execution_requested`
Emitted when user requests execution.

```json
{
  "standard": "near-outlayer",
  "version": "1.0.0",
  "event": "execution_requested",
  "data": [{
    "request_data": "{...}",
    "data_id": [0,1,2,...],
    "timestamp": 1234567890
  }]
}
```

### `execution_completed`
Emitted when execution is completed.

```json
{
  "standard": "near-outlayer",
  "version": "1.0.0",
  "event": "execution_completed",
  "data": [{
    "sender_id": "user.testnet",
    "code_source": {...},
    "resources_used": {...},
    "success": true,
    "timestamp": 1234567890
  }]
}
```

## Build & Deploy

### Build

```bash
./build.sh
```

### Deploy with init

```bash
near contract deploy outlayer.testnet use-file res/local/outlayer_contract.wasm with-init-call new json-args '{"owner_id":"owner.outlayer.testnet","operator_id":"worker.outlayer.testnet"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
```

### Set event standard

```
near contract call-function as-transaction dev.outlayer.testnet set_event_metadata json-args '{"standard":"near-outlayer-dev"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as owner.outlayer.testnet network-config testnet sign-with-keychain send
```


### Set operator account

```
near contract call-function as-transaction dev.outlayer.testnet set_operator json-args '{"new_operator_id":"dev.outlayer.testnet"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as owner.outlayer.testnet network-config testnet sign-with-keychain send
```

### Set testnet USDC

near contract call-function as-transaction dev.outlayer.testnet set_payment_token_contract json-args '{"token_contract":"usdc.fakes.testnet"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as owner.outlayer.testnet network-config testnet sign-with-keychain send

# register storage
near contract call-function as-transaction usdc.fakes.testnet storage_deposit json-args '{"account_id": "dev.outlayer.testnet"}' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' sign-as dev.outlayer.testnet network-config testnet sign-with-keychain send

### Deploy without init

A deploy that changes the state shape runs `migrate` in the same transaction
(or straight after). `get_storage_version` answers the shape the code expects:
`"11"` adds `project_transfer_acceptances` (from `"10"`).

```bash
near contract deploy dev.outlayer.testnet use-file res/local/outlayer_contract.wasm without-init-call network-config testnet sign-with-keychain send
```

```bash
near contract deploy outlayer.testnet use-file res/local/outlayer_contract.wasm without-init-call network-config testnet sign-with-keychain send

 near contract call-function as-transaction outlayer.testnet migrate json-args {} prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as outlayer.testnet network-config testnet sign-with-keychain send
```

# Mainnet
```
near contract deploy outlayer.near use-file res/local/outlayer_contract.wasm without-init-call network-config mainnet sign-with-keychain send

near contract deploy outlayer.near use-file res/local/outlayer_contract.wasm with-init-call migrate json-args '{}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config mainnet sign-with-keychain send

near contract call-function as-transaction outlayer.near migrate json-args {} prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as outlayer.near network-config mainnet sign-with-keychain send

near contract call-function as-transaction outlayer.near new json-args '{"owner_id":"owner.outlayer.near","operator_id":"worker.outlayer.near"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as outlayer.near network-config mainnet sign-with-keychain send

near contract call-function as-transaction outlayer.near set_payment_token_contract json-args '{"token_contract":"17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as owner.outlayer.near network-config mainnet sign-with-keychain send

near contract call-function as-transaction 17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1 storage_deposit json-args '{"account_id": "outlayer.near"}' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' sign-as outlayer.near network-config mainnet sign-with-keychain send
```

### Test

```bash
cargo test
```

## License

MIT
