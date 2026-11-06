# OutLayer Smart Contract

NEAR contract for off-chain WASM execution through yield/resume, plus the
on-chain records the rest of OutLayer reads: projects and their versions,
encrypted secrets, payment keys, and encrypted wallet policies.

- Testnet: `outlayer.testnet`
- Mainnet: `outlayer.near`

`get_config` answers `[owner, operator]`. The operator is the worker
registration account (`worker.outlayer.near`; `worker.outlayer.testnet` on
testnet); each TEE worker holds a function-call key on it scoped to
`resolve_execution`, `submit_execution_output_and_resolve`, `resume_topup` and
`resume_delete_payment_key`.

## Features

- **Yield/resume**: `request_execution` creates a yield promise; a worker runs
  the code and resumes it with the result, which the calling contract receives
  as the return value.
- **Resource limits** on instructions, memory and time, with hard caps.
- **Usage-based pricing**: the deposit covers the worst case for the limits; the
  unused part is refunded at settlement.
- **Stale request cancellation** by the sender after a timeout.
- **Projects**: named, versioned code with its own storage namespace.
- **Secrets**: ciphertext and an access condition stored here; the keystore
  (TEE) decrypts and judges the condition.
- **Payment keys** for the HTTPS API, and **wallet policies** for agent custody.
- **Owner controls**: operator, pricing, pause, project prices, subscription plans.

## Contract API

Who may call: *owner* = `assert_owner` (the contract owner), *operator* =
`assert_operator` (the operator account), *private* = the contract itself
(callbacks). Everything else is open to any account, acting on its own records
(the predecessor).

### Execution

#### `request_execution` (payable)

`request_execution(source, resource_limits?, input_data?, secrets_ref?, response_format?, payer_account_id?, params?)`

```bash
near call outlayer.testnet request_execution '{
  "source": {
    "Project": {"project_id": "alice.testnet/my-app", "version_key": null}
  },
  "resource_limits": {
    "max_instructions": 1000000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  },
  "input_data": "{\"key\": \"value\"}"
}' --accountId user.testnet --deposit 0.01 --gas 100000000000000
```

- `source` is an `ExecutionSource`:
  - `{"Project": {"project_id", "version_key"}}` — the normal case.
    `version_key: null` runs the active version; otherwise it names a version
    (its wasm hash). The run gets the project's storage namespace.
  - `{"WasmUrl": {"url", "hash", "build_target"}}` — runs a published file
    directly, e.g.
    `{"WasmUrl": {"url": "https://main.fastfs.io/alice.near/outlayer.near/<sha256>.wasm", "hash": "<sha256>", "build_target": "wasm32-wasip2"}}`.
    The contract requires `url` to be `https://` (at most 2048 bytes, no
    whitespace) and `hash` to be the SHA-256 as 64 lowercase hex characters; the
    worker also refuses a URL with an explicit port and a file whose bytes do
    not match the hash.
  - `{"GitHub": {"repo", "commit", "build_target"}}` — accepted by the contract,
    but building from sources is off by default on the coordinator
    (`BUILDS_ENABLED`), so such a request is refused off chain. Publish a
    `.wasm` and use `Project` or `WasmUrl`.
- `resource_limits` — `{max_instructions?, max_memory_mb?, max_execution_seconds?}`;
  a field left out takes its default (1 billion, 128 MB, 60 s). **Always pass
  it, even as `{}`**: a request without `resource_limits` is compile-only and
  runs nothing.
- `input_data` — the guest's stdin. 10,000 bytes and more is left out of the
  event and read by the worker from state (`get_request`).
- `secrets_ref` — `{profile, account_id}`: the secret row the run asks the
  keystore for. `profile` must satisfy the rule `store_secrets` applies (1–64
  bytes of letters, digits, `-` or `_`); a reference no row could match is
  refused before the request yields.
- `response_format` — `Text` (default), `Json` or `Bytes`.
- `payer_account_id` — who receives the NEAR refund; default the caller.
- `params` — `RequestParams`:
  - `attached_usd` (U128, stablecoin minimal units, `1000000` = $1) — payment to
    the project's owner, debited from the caller's stablecoin balance in the
    contract (`ft_on_transfer` with `deposit_balance`). `Project` source only.
  - `use_bound_identity` (bool) — run the guest under the caller's bound
    account name.
  - `force_rebuild`, `store_on_fastfs`, `compile_only` — build controls.
    `force_rebuild` is refused for a `WasmUrl` source; `store_on_fastfs`
    requires `force_rebuild`; compile-only refuses a non-empty `input_data`.
  - `project_uuid` is set by the contract from a `Project` source and cleared
    otherwise; a value the caller passes is ignored.

**Whose identity.** The `execution_requested` payload carries `sender_id` =
the transaction's signer and `predecessor_id` = the calling account. The
keystore judges a secret's condition against the signer (see
[Access conditions](#access-conditions)). The stored request's `sender_id` is
the predecessor: it is the account that may cancel, and the one the
stablecoin is debited from and returned to.

**Priced projects.** A project with a price (`get_project_pricing`) is charged
per operation: `input_data` must be a JSON object of at most 10,000 bytes with
a non-empty string `"operation"` at the top level, the project must sell that
operation, and `attached_usd` must be at least its price. The excess comes back
to the caller's stablecoin balance at settlement. Not applied to compile-only
requests.

**Deposit.** `estimate_execution_cost(resource_limits, input_len)` is what to
attach: the compute estimate for the limits
(`base_fee + max_instructions/1e6 × per_million_instructions_fee + max_execution_seconds × 1000 × per_ms_fee`),
plus — for an `input_data` longer than 32 KB — 0.00001 NEAR per byte above
that, held while the request is pending and returned at settlement. A
compile-only request requires the base fee.

**Gas.** The settlement callback is created with 50 TGas taken from the gas
attached to the call, so attach more than that (the example uses 100 TGas).
Above 32 KB of input it gets 25 MGas more per byte (about 52 TGas more for
2 MiB).

**Return value.** The calling contract receives the output as a JSON value:
the guest's JSON for `Json`, a string for `Text`, base64 for `Bytes`, and
`null` when the run failed or produced nothing.

**Limits.** `get_max_limits` answers `[max_instructions, max_execution_seconds, max_compilation_seconds]`
= `[500000000000, 180, 300]`; `max_memory_mb` is capped at 4096 (wasm32's
bound). A request above a cap is refused at the door.

**What a run is charged.** A success pays
`base_fee + instructions/1e6 × per_million_instructions_fee + time_ms × per_ms_fee`,
plus `compile_time_ms × per_compile_ms_fee` when the worker compiled, capped at
the NEAR attached minus the input storage part. A failed run pays the same
formula on what the worker reports it used, capped the same way; a failure
before the guest ran reports little or nothing and costs about the base fee. A
run the chain's yield window (200 blocks) outlived pays the base fee. The
storage part of a large input always comes back. The stablecoin comes back
whole when the run fails or times out; on a success the price goes to the
project (split with the author for a priced project), less the guest's own
refund, and any change returns to the caller.

#### `cancel_stale_execution`

Only the request's sender, only after 10 minutes. Returns the whole of the
stablecoin and the NEAR above the charge, the storage part of a large input
always included. The charge is the base fee when no output was delivered — as
a timed-out request pays — and the compute estimate for the limits when the
worker has delivered the output through the 2-call flow and the callback never
settled it: the run happened and its output is readable with
`get_pending_output`.

```bash
near call outlayer.testnet cancel_stale_execution '{"request_id": 123}' --accountId user.testnet
```

### Operator Functions

#### `resolve_execution`

`resolve_execution(request_id, response)` — operator. Resumes the yield with an
`ExecutionResponse`; used when the response fits the yield-resume payload limit
(1024 bytes).

```bash
near call outlayer.testnet resolve_execution '{
  "request_id": 0,
  "response": {
    "success": true,
    "output": {"Text": "Hello, NEAR!"},
    "error": null,
    "resources_used": {"instructions": 1000000, "time_ms": 100, "compile_time_ms": null},
    "compilation_note": null,
    "refund_usd": null
  }
}' --accountId worker.outlayer.testnet
```

`refund_usd` is the guest's refund of part of `attached_usd`, clamped to the
price.

#### `submit_execution_output_and_resolve`

`submit_execution_output_and_resolve(request_id, output, success, error, resources_used, compilation_note)`
— operator. Stores a large output in the request and resumes the yield in the
same call; the callback reads the output from state. This flow carries no
`refund_usd`.

`submit_execution_output(request_id, output)` (operator) stores the output
alone, to be followed by `resolve_execution`; worker keys are not scoped to it.

#### `resume_topup` / `resume_delete_payment_key`

`resume_topup(data_id, result)` and `resume_delete_payment_key(data_id, result)`
— operator. Resume the yields of a payment-key top-up and delete; `data_id` is
hex. `result` is `{"Success": {"new_encrypted_data"}}` / `{"Error": {"message"}}`
for a top-up, `"Success"` / `{"Error": {"message"}}` for a delete. Both panic
when no yield is waiting (it timed out and was settled, or was already
resumed).

### Owner Functions

All `assert_owner`.

| Method | What it does |
|---|---|
| `set_owner(new_owner_id)` | Hand the owner role on |
| `set_operator(new_operator_id)` | Change the operator account |
| `set_paused(paused)` | Pause: refuses `request_execution`, `create_project`, `add_version`, `accept_project_transfer`, `store_wallet_policy`, `freeze_wallet`, `unfreeze_wallet`, `set_storage_refund_to`, `top_up_payment_key_with_near` |
| `set_pricing(base_fee?, per_million_instructions_fee?, per_ms_fee?, per_compile_ms_fee?, base_fee_usd?, per_million_instructions_fee_usd?, per_sec_fee_usd?, per_compile_ms_fee_usd?)` | NEAR prices (yoctoNEAR) and HTTPS API prices (stablecoin minimal units); each `U128` string, an omitted one is unchanged |
| `set_payment_token_contract(token_contract?)` | The stablecoin `ft_on_transfer` accepts and earnings are paid in; `null` clears it. The contract account must be registered on the token (`storage_deposit`) |
| `set_subscription_plans(plans)` | Replace the plan list: `[{index, name, price_usd, active}]`, at most 16, unique indexes, each named and priced; an index already in the list keeps its name |
| `set_project_pricing(project_id, pricing)` | Price an existing project: `{author_account_id, operations: [{operation, price_usd, developer_share_bp}]}`, 1–32 unique operations, share ≤ 10000 bp |
| `remove_project_pricing(project_id)` | Unprice a project |
| `set_event_metadata(standard?, version?)` | The NEP-297 `standard` / `version` events carry |
| `emergency_cancel_execution(request_id)` | Cancel one pending request; refunds the whole NEAR deposit and the stablecoin |
| `cancel_pending_requests(request_ids)` → `u64` | Cancel a list; refunds the NEAR deposit only — the request's `attached_usd` is not returned to the sender's stablecoin balance on this path |
| `clear_all_pending_requests(limit?)` → `u64` | Cancel up to `limit` (default 100) pending requests from id 0; refunds NEAR and stablecoin |

```bash
near call outlayer.testnet set_pricing '{"base_fee": "1000000000000000000000"}' --accountId <owner>
```

### View Functions

| Method | Answer |
|---|---|
| `get_request(request_id)` | The pending `ExecutionRequest`, or `null` once settled |
| `get_pending_request_ids(from_index?, limit?)` | Pending ids (default limit 100) |
| `get_pending_output(request_id)` / `has_pending_output(request_id)` | Output delivered through the 2-call flow, not yet settled |
| `get_stats()` | `[total_executions, total_fees_collected]` |
| `get_pricing()` | `[base_fee, per_million_instructions_fee, per_ms_fee, per_compile_ms_fee]` |
| `get_pricing_full()` | The NEAR prices and the HTTPS API prices (`base_fee_usd`, `per_million_instructions_fee_usd`, `per_sec_fee_usd`, `per_compile_ms_fee_usd`) |
| `estimate_execution_cost(resource_limits?, input_len?)` | Deposit for `request_execution`, yoctoNEAR |
| `get_max_limits()` | `[max_instructions, max_execution_seconds, max_compilation_seconds]` |
| `get_config()` | `[owner, operator]` |
| `get_event_metadata()` | `[standard, version]` |
| `is_paused()` | `bool` |
| `get_payment_token_contract()` | The configured stablecoin, or `null` |
| `get_subscription_plans()` | The whole plan list, withdrawn plans included |
| `get_project_pricing(project_id)` | The project's price list, or `null` |
| `get_project_max_price(project_id)` | The most one call can cost; `"0"` when unpriced |
| `get_priced_projects(from_index?, limit?)` / `get_priced_project_count()` | Priced project ids (default 100, at most 500 per page) |
| `get_developer_earnings(account_id)` | Stablecoin earned and not withdrawn |
| `get_user_stablecoin_balance(account_id)` | Stablecoin available for `attached_usd` |
| `get_storage_version()` | The state layout the code expects (`"12"`) |

```bash
near view outlayer.testnet get_request '{"request_id": 123}'
```

### Stablecoin: deposits and earnings

The configured stablecoin arrives through NEP-141 `ft_transfer_call` to this
contract; `ft_on_transfer` refuses any other token. `msg` is one of:

- `{"action": "deposit_balance"}` — credits the sender's balance for
  `attached_usd`.
- `{"action": "top_up_payment_key", "nonce": N, "owner": "<optional>"}` — tops
  up a payment key (at least 10000 = $0.01; `owner` defaults to the sender).
  The worker re-encrypts the key's balance and resumes; a failure or a timeout
  returns the tokens.
- `{"action": "buy_subscription", "nonce": N, "plan": P, "owner": "<optional>"}` —
  buys plan `P` for an existing key. A payment short of the plan, an unknown or
  withdrawn plan, or a missing key refuses the whole transfer; an overpayment
  is kept and reported in the event.

`withdraw_developer_earnings()` (payable, at least 1 yoctoNEAR) transfers the
caller's whole earnings balance; the balance is restored if the transfer fails.

### Project Functions

A project is `{owner}/{name}`: the name is 1–64 bytes of ASCII letters,
digits, `-` or `_` (a Cyrillic `а` in `polymаrket` is not a name — it would
read as the real one). The owner calls every write with the bare name; the
caller is the owner.

- `create_project(name, source)` (payable) — `source` is a `CodeSource`
  (`WasmUrl` or `GitHub`, held to the same rules as in `request_execution`);
  it becomes the active version. Attach the storage deposit; the panic names
  the figure and the excess is refunded.
- `add_version(project_name, source, set_active)` (payable).
- `set_active_version(project_name, version_key)`.
- `remove_version(project_name, version_key)` — not the active one; refunds
  the version's deposit.
- `delete_project(project_name)` — refunds the project's deposit and emits
  `system_event` `ProjectStorageCleanup { project_id, project_uuid, timestamp }`
  so workers erase its storage.

A version key is the wasm hash for a `WasmUrl` source and `{repo}@{commit}`
for a `GitHub` one.

Views: `get_project(project_id)`, `list_user_projects(account_id)`,
`get_version(project_id, version_key)`,
`list_versions(project_id, from_index?, limit?)` (default 50, at most 100),
`get_version_count(project_id)`, `has_project_uuid(project_uuid)`.

#### `accept_project_transfer` (payable)

A project moves only onto an acceptance given by the account that will own
it, for exactly that project and that owner. Without one, `transfer_project`
is refused — so nobody can put their code under a name in another account's
namespace (`connectors.outlayer.near/<name>` before the real one exists)
without that account asking for it.

```bash
# bob agrees to take alice.testnet/my-app. The deposit pays for the record and
# comes back when it is consumed or revoked; estimate_transfer_acceptance_cost
# quotes it (about 0.001–0.003 NEAR, by the length of the names).
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
owner's, so the contract owner unprices it (`remove_project_pricing`) first.
Emits `ProjectTransferred { old_project_id, new_project_id, project_uuid, old_owner, new_owner }`.

#### `estimate_transfer_acceptance_cost`

```bash
near view outlayer.testnet estimate_transfer_acceptance_cost '{"new_owner": "bob.testnet", "from": "alice.testnet", "name": "my-app"}'
```

The deposit `accept_project_transfer` will charge, in yoctoNEAR.

### Wallet Policy Functions

A custody wallet's policy is stored here encrypted by the keystore; the
coordinator keeps a readable copy for its own checks, and the keystore reads
the on-chain entry before it signs. The account that sends
`store_wallet_policy` becomes its controller.

#### `store_wallet_policy` (payable)

`store_wallet_policy(wallet_pubkey, encrypted_data, wallet_signature, version, locked, valid_until, storage_refund_to?)`.
Create or update a policy. `wallet_pubkey` is `ed25519:<hex32>` or
`secp256k1:<hex33>`; `encrypted_data` is at most 100 KB. Needs a signature by
the wallet's own key over
`sha256("store_wallet_policy:v2:{wallet_pubkey}:{version}:{locked 0|1}:{valid_until}:{len}:{encrypted_data}:{caller}")`
(the keystore makes it) and a storage deposit (`estimate_wallet_policy_cost`).
An update must come from the same controller and keeps the frozen flag. Emits
`WalletPolicyUpdated { wallet_pubkey, owner, encrypted_data, frozen, version, locked }`.

`version` is the stored version plus one (a first policy: 1), checked before
the signature — a stale one fails with `policy version is N, this signature
was made for M` — so a signature is good for exactly one write. `valid_until`
(unix seconds, seven days from signing) is checked the same way — `this policy
signature expired at T` — so a signature is good for a while, not for ever.
`locked` is the new policy's `approval.locked` as the keystore read it from
the plaintext. All three come from the keystore's `sign-policy` answer and are
inside the signature. The contract keeps them beside the entry (`policy_meta`, absent =
version 0, unlocked). **While the stored policy is locked**, the keystore
signs the next write only with the policy's approvers' quorum, and the
contract refuses `delete_wallet_policy`; freezing and thawing are untouched.

`storage_refund_to` (optional) names who the storage deposit goes back to —
for a sponsor that pays it while the owner signs. It is set only when the
policy is CREATED: an update that names it fails. From then on every refund
goes to it — the excess of the creating call, the difference when an update
shrinks the policy, and the whole deposit on `delete_wallet_policy`. The owner
keeps every power over the policy itself (update, freeze, delete); it cannot
change where the deposit goes. That includes the excess of the owner's own
attachment on an update: attach exactly `estimate_wallet_policy_cost`, or the
rest goes to the beneficiary. Without the argument, refunds go to the caller.
The argument is covered by the owner's transaction signature, so a NEP-366
relayer cannot change it.

```bash
near contract call-function as-transaction outlayer.testnet store_wallet_policy json-args '{
  "wallet_pubkey": "ed25519:<hex>", "encrypted_data": "<base64>",
  "wallet_signature": "<hex>", "version": 1, "locked": false, "valid_until": 1700000000,
  "storage_refund_to": "sponsor.testnet"
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

`StorageItem` is what a refundable deposit is held for. It has one variant,
`WalletPolicy { wallet_pubkey }`.

#### `delete_wallet_policy`

Controller only, and refused while the policy is locked (`policy is locked:
store an unlocked policy with the approvers' quorum first`). Returns the whole
deposit to the beneficiary when one is set, otherwise to the caller, and drops
the beneficiary and the version record: a policy created again under the key
starts without one, at version 1. The `WalletPolicyDeleted` event carries
`refunded_to`.

#### `freeze_wallet` / `unfreeze_wallet`

Controller only, no wallet signature: the emergency stop for a compromised
agent key. Emit `WalletFrozenChanged { wallet_pubkey, owner, frozen }`.

#### Views

- `get_wallet_policy(wallet_pubkey)` → `{owner, encrypted_data, frozen, updated_at, storage_refund_to, storage_deposit, version, locked}` or `null`. A sponsor checks `storage_refund_to` before it pays; `version` is what the next write must exceed by one.
- `get_wallet_policies_by_owner(owner)` → `[{wallet_pubkey, owner, frozen, updated_at, storage_refund_to, version, locked}]`.
- `has_wallet_policy(wallet_pubkey)` → `bool`.
- `estimate_wallet_policy_cost(wallet_pubkey, encrypted_data, storage_refund_to?)` → yoctoNEAR as a string; with `storage_refund_to` it includes the beneficiary's record, as the store will charge it.

### Secrets Management Functions

The contract stores ciphertext and an access condition; it never sees a
plaintext. The encryption key comes from the keystore through the API
(`POST https://api.outlayer.ai/secrets/pubkey`), not from this contract;
`outlayer secrets set` (CLI) and the dashboard do the encryption and the
`store_secrets` call.

#### `store_secrets` (payable)

`store_secrets(accessor, profile, encrypted_secrets_base64, access, vault_id)`.
Store encrypted secrets under `(accessor, profile, caller)`. The accessor is:

- `{"Project": {"project_id"}}` — every version of a project; the project must
  exist.
- `{"WasmHash": {"hash"}}` — one build; 64 hex characters, stored lower-case.
- `{"System": "PaymentKey"}` — a payment key (see
  [Payment keys](#payment-keys)).
- `{"Repo": {"repo", "branch"}}` — accepted by the contract and read with a
  fallback from a branch to `branch: null`; the CLI refuses it for new values,
  since OutLayer runs published `.wasm` builds.

`profile` names the row: 1–64 bytes of letters, digits, `-` or `_`; a profile of
64 lowercase hex characters names an agent and is refused unless the owner is
that implicit account. The same rule refuses, at `request_execution`, a
`secrets_ref` no row could match.

`vault_id`: pass it explicitly, `null` for the default OutLayer master, or the
vault account whose master encrypted the ciphertext. `null` leaves an existing
vault binding of the row in place; `unbind_secret_vault(accessor, profile)`
removes one.

A store on an existing row replaces the ciphertext and the condition; the
deposit already held counts towards the new size, and the excess comes back.

```bash
# 1. Estimate storage cost for the exact slot, ciphertext and condition.
near view outlayer.testnet estimate_storage_cost '{
  "accessor": {"Project": {"project_id": "alice.testnet/my-app"}},
  "profile": "default",
  "owner": "alice.testnet",
  "encrypted_secrets_base64": "<base64>",
  "access": "AllowAll",
  "vault_id": null
}'
# Output: yoctoNEAR as a string

# 2. Store; attach at least the estimate, the excess is refunded.
near call outlayer.testnet store_secrets '{
  "accessor": {"Project": {"project_id": "alice.testnet/my-app"}},
  "profile": "default",
  "encrypted_secrets_base64": "<base64>",
  "access": "AllowAll",
  "vault_id": null
}' --accountId alice.testnet --deposit 0.01
```

#### `estimate_storage_cost`

`estimate_storage_cost(accessor, profile, owner, encrypted_secrets_base64, access, vault_id)`
→ yoctoNEAR. Refuses a condition the store would refuse. The size counted:

- 40 bytes of record overhead;
- the key: accessor, profile and owner, Borsh-encoded with length prefixes;
- the value: the ciphertext (+4), the condition's JSON (+10), and 32 bytes of
  timestamps and deposit;
- 64 bytes for the owner's index entry;
- with a vault binding (passed, or already on the row): 40 + the key + 68;
- a new payment key adds the owner's nonce floor entry, once per owner.

All at 0.00001 NEAR per byte. A large `Whitelist` costs more than `AllowAll`.

#### `update_access` (payable)

`update_access(accessor, profile, new_access)`. Change who may read a stored
secret. The condition moves and the ciphertext stays, so no value is
re-entered and a TEE-generated key is never lost. Keyed on
`(accessor, profile, caller)`: only the owner of the row can change it, and a
non-owner's call panics with `Secrets not found`. This is how an owner hands a
secret to an agent and takes it back — the agent names `{account_id: owner,
profile}` in `secrets_ref`.

Payable, because a condition is stored bytes: a `Whitelist` of two thousand
accounts occupies some fifty kilobytes. The row is re-priced against the new
condition and the deposit already held counts towards it, so narrowing refunds
the difference, an edit that does not change the size needs nothing, and only
growth asks for more. Call `estimate_storage_cost` with the row's existing
`encrypted_secrets_base64` and the new condition to learn the figure;
attaching it is always sufficient, and the excess comes back in the same
transaction.

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

#### `delete_secrets`

`delete_secrets(accessor, profile)` — the caller's row; refunds its storage
deposit and drops its vault binding. It accepts any accessor, a payment key
included, and tells the coordinator nothing: delete a payment key with
`delete_payment_key`.

```bash
near call outlayer.testnet delete_secrets '{
  "accessor": {"Project": {"project_id": "alice.testnet/my-app"}},
  "profile": "default"
}' --accountId alice.testnet
```

#### `store_agent_secret` (payable) / `delete_agent_secret`

`store_agent_secret(agent_pubkey, accessor, profile, encrypted_secrets_base64, access, vault_id, wallet_signature)`
stores a secret OWNED by an agent wallet — the implicit account of the ed25519
`agent_pubkey` — paid for by the caller, who receives every refund. The
accessor is `Project` or `WasmHash` only. `wallet_signature` is the wallet
key's signature, made by the keystore, over the SHA-256 of
`store_secrets_for:v1:{agent_pubkey}:{len(accessor)}:{accessor}:{profile}:{encrypted_secrets_base64}:{caller}:{vault_id or empty}:{access as JSON}`,
where `{accessor}` is the project id, or `wasm:{hash}`.

`delete_agent_secret(agent_pubkey, accessor, profile, wallet_signature)` removes
one on the signature of the same key over
`delete_agent_secret:v1:{agent_pubkey}:{len(accessor)}:{accessor}:{profile}:{caller}`;
the deposit goes to the caller. Neither accepts a payment key.

#### Reads

- `get_secrets(accessor, profile, owner)` → `{encrypted_secrets, access, created_at, updated_at, storage_deposit, accessor}` or `null`.
- `get_secret_with_vault(accessor, profile, owner)` → `{profile, vault_id}` (the keystore reads this).
- `get_secret_vault(accessor, profile, owner)` → the bound vault, or `null`.
- `secrets_exist(accessor, profile, owner)` → `bool`.
- `list_user_secrets(account_id, from_index?, limit?)` → one page of
  `{accessor, profile, created_at, updated_at, storage_deposit, access}`.
  Omitting the paging arguments gives the first 100, not the whole set; `limit`
  is capped at 500. Ask for the next page until one comes back short.
- `list_profiles(_repo, _branch)` always returns `[]`; use `list_user_secrets`.

```bash
near view outlayer.testnet list_user_secrets '{"account_id": "alice.testnet", "from_index": 0, "limit": 100}'
```

#### Access conditions

`access` (on `store_secrets` and `update_access`) is an `AccessCondition`, evaluated
by the keystore inside the TEE against the account the run is attributed to — the
transaction's SIGNER on chain (a contract that relays `request_execution` is the
predecessor and pays, but the signer is the one judged — unless the condition
says otherwise with `Predecessor`), a payment key's owner over HTTPS — never
against a name the call claims. Variants (12): `"AllowAll"`;
`{"Whitelist": {"accounts": [...]}}` (exact match);
`{"AccountPattern": {"pattern": "..."}}` (a regex anchored to the whole id);
`{"NearBalance": {"operator", "value": "<yocto>"}}`; `{"FtBalance": {"contract",
"operator", "value"}}`; `{"NftOwned": {"contract", "token_id"}}` (`token_id`
optional); `{"DaoMember": {"dao_contract", "role"}}`; `{"ValidUntil": {"until_ns":
"<nanoseconds since the epoch, as a string>"}}` (admits strictly before that
instant); `{"WasmHash": {"hash": "<SHA-256 of the build, 64 lowercase hex>"}}`
(admits only a run of that exact build — the keystore compares it with the hash
the worker measured on the bytes it executes; `update_access` moves a row to the
next build without re-encrypting); `{"Predecessor": {"condition": ...}}` (judges
the condition it wraps on the account that CALLED the contract —
`predecessor_account_id`: the relaying contract, or the signer on a direct call —
so `And[Whitelist[me], Predecessor{Whitelist[me]}]` admits only the owner's own
direct calls and `Predecessor{Whitelist[dao]}` only calls through that DAO; over
HTTPS the payment key's owner is judged as the calling account too, so there the
wrapper adds nothing); `{"Logic": {"operator": "And" | "Or", "conditions": [...]}}`
and `{"Not": {"condition": ...}}` to combine them. Comparison operators are
`Gte`, `Lte`, `Gt`, `Lt`, `Eq`, `Ne`. The contract stores the condition without
evaluating it; the Borsh layout of `SecretProfile.access` is the variant order,
so new variants are only ever appended.

The contract stores no condition the keystore would refuse to judge, so both
`store_secrets` and `update_access` refuse one past these bounds — and
`estimate_storage_cost` quotes no such condition either:

* at most **5** leaves that can only be answered by asking the chain
  (`NearBalance`, `FtBalance`, `NftOwned`, `DaoMember`). They are asked one
  after another from inside the enclave, against contracts the row's owner
  chose, and a shared keystore waits for all of them;
* at most **16** `AccountPattern` leaves and **4096 bytes** of pattern text in
  all. A pattern's compiled size is not its text size, and the keystore
  compiles every pattern of a condition before judging a decrypt;
* every `WasmHash` leaf is 64 lowercase hex characters;
* every `Logic` node holds at least one condition (an empty `And` would admit
  everyone).

A whitelist is answered from the condition itself, so neither its size nor the
number of whitelist leaves is bounded — the only cost is storage, which the
row's owner pays for.

### Payment keys

A payment key is a secret under the `{"System": "PaymentKey"}` accessor whose
profile is its nonce, created with `store_secrets`. The nonce is a number from 1
to 2147483647 (0 is reserved for keys the coordinator issues itself), and a key
is written once: a second store at the same nonce is refused. Creating one
emits `system_event` `TopUpPaymentKey` with amount 0, which registers the key
with the coordinator.

A nonce is handed out to an owner once: `store_secrets` refuses a payment key
at or below the owner's floor — the highest nonce the contract has seen them
create or delete — with "has already been used". The coordinator keeps a
deleted key's row under `(owner, nonce)`, and a new key there would bring it
back with the old balance and grants.

- `get_next_payment_key_nonce({account_id})` — the lowest nonce a new key may
  take: one above both the live keys and the floor.
- `get_payment_key_nonce_floor({account_id})` — the floor; 0 when none is
  recorded.

The floor is raised when a key is created and when one is deleted, so it holds
every nonce the contract has seen come or go; a key older than the owner's
floor entry is recorded when it is deleted. Its entry is paid once, by the
owner's first key (included in `estimate_storage_cost`), and is not refunded:
it outlives every key.

- `delete_payment_key(nonce)` (payable, at least 1 yoctoNEAR) — yields until
  the worker has deleted the key in the coordinator (`DeletePaymentKey` event,
  `resume_delete_payment_key`), then removes the row and refunds its storage
  deposit. The key's unspent balance is not returned. On an error or a timeout
  the key stays.
- Top-up with the stablecoin: `ft_on_transfer` with `top_up_payment_key` (see
  [Stablecoin](#stablecoin-deposits-and-earnings)).
- `top_up_payment_key_with_near(nonce, swap_contract_id)` (payable) — **mainnet
  only** (NEAR Intents). Wraps the attached NEAR minus 0.01 NEAR to wNEAR,
  sends it to `swap_contract_id` and requests a swap to the stablecoin through
  the `publishintent.near/payment-keys-with-intents` project. Requires at least
  0.01 NEAR above that 0.01 NEAR and an existing key of the caller's.
- `top_up_payment_key_with_token(nonce, token_id, amount, swap_contract_id)` is
  disabled: it always panics.

## Events

NEP-297 logs, `EVENT_JSON:{"standard", "version", "event", "data": [ … ]}`;
`data` is a one-element array. `standard` and `version` are the deployment's
(`get_event_metadata`; `near-outlayer` / `1.0.0` unless set).

### `execution_requested`

Emitted by `request_execution`; workers pick requests up from it.

```json
{
  "standard": "near-outlayer",
  "version": "1.0.0",
  "event": "execution_requested",
  "data": [{
    "request_data": "{\"request_id\":0,\"sender_id\":\"...\",\"predecessor_id\":\"...\",\"code_source\":{...},\"resource_limits\":{...},\"input_data\":\"...\",\"input_data_in_state\":false,\"secrets_ref\":null,\"response_format\":\"Text\",\"payment\":\"...\",\"attached_usd\":\"0\",\"timestamp\":0,\"compile_only\":false,\"force_rebuild\":false,\"store_on_fastfs\":false,\"use_bound_identity\":false,\"project_uuid\":null,\"project_id\":null}",
    "data_id": [0,1,2,...],
    "timestamp": 1234567890
  }]
}
```

`request_data` is a JSON string; `data_id` is the yield's 32 bytes.

### `execution_completed`

Emitted at settlement when the worker resumed the yield (not on a yield
timeout).

```json
{
  "standard": "near-outlayer",
  "version": "1.0.0",
  "event": "execution_completed",
  "data": [{
    "sender_id": "user.testnet",
    "code_source": {...},
    "resources_used": {"instructions": 0, "time_ms": 0, "compile_time_ms": null},
    "success": true,
    "error_message": null,
    "payment_charged": "...",
    "payment_refunded": "...",
    "compilation_note": null,
    "timestamp": 1234567890
  }]
}
```

### `system_event`

`data` is `[{"<Variant>": {...}}]`, one of: `TopUpPaymentKey`,
`DeletePaymentKey`, `SubscriptionPurchased`, `WalletPolicyUpdated`,
`WalletPolicyDeleted`, `WalletFrozenChanged`, `StorageRefundToChanged`,
`ProjectTransferred`, `ProjectTransferAccepted`, `ProjectTransferRevoked`,
`ProjectStorageCleanup`.

## Build & Deploy

### Build

```bash
./build.sh   # cargo near build non-reproducible-wasm → res/local/outlayer_contract.wasm
```

### Test

```bash
cargo test
```

### Initialize

`new(owner_id, operator_id?, event_standard?, event_version?)`; the operator
defaults to the owner.

```bash
near contract deploy <contract-account> use-file res/local/outlayer_contract.wasm with-init-call new json-args '{"owner_id":"<owner>","operator_id":"<operator>"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
```

### Upgrade

The contract is upgraded by redeploying it with the contract account's
full-access key, without a vote or a delay; see
[Governance at this stage](../docs/NON_CUSTODIAL.md#governance-at-this-stage).

`get_storage_version` answers the state layout the code expects. A deploy that
changes the layout calls `migrate` (private: signed by the contract account) in
the same transaction; `migrate` reads the previous layout (`"10"`) and writes
`"11"`, and fails on any other state. A deploy that keeps the layout calls
nothing.

```bash
near contract deploy outlayer.testnet use-file res/local/outlayer_contract.wasm without-init-call network-config testnet sign-with-keychain send

near contract deploy outlayer.near use-file res/local/outlayer_contract.wasm with-init-call migrate json-args '{}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config mainnet sign-with-keychain send
```

## License

Apache-2.0
