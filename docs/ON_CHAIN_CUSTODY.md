# On-chain custody: an agent with a wallet contract

> **On testnet now** (`https://testnet-api.outlayer.ai`); on mainnet with the
> next release. Until then `api.outlayer.ai` answers `404` on every route
> below.

An agent with on-chain custody keeps its main balance in a **wallet contract**:
a NEAR account that runs the two-key variant of the
[NEAR Intents wallet contract](https://github.com/near/intents/tree/main/contracts/wallet).
The wallet contract executes a request only under two signatures: one by the
agent's own Ed25519 key and one by a key held in OutLayer's Intel TDX enclave.
The enclave signs only an operation the owner's policy allows, and the chain
checks both signatures.

This document is the reference: the model, the keys, the setup, an operation
with every route, what each party's compromise reaches, the byte formats, and
the operator's configuration.

- API base: `https://api.outlayer.ai`
- The owner's setup page: `https://app.outlayer.ai/wallet/custody`
- OpenAPI: tag "On-chain custody" in the [API spec](https://github.com/out-layer/api-spec)
- SDK: `@outlayer/sdk` (`openSetup`, `collectSetup`, `AgentKey`, `WalletContract`)

## 1. Two modes of custody

Every OutLayer wallet keeps its keys in the enclave and signs within its
owner's policy: that is TEE custody, and it is what an agent gets when it
registers. On-chain custody is a second place for an agent's funds, added to
the same wallet by its owner. An agent with on-chain custody uses both: the
wallet contract holds the main balance, and the OutLayer wallet is its
**working account**.

| | TEE custody | On-chain custody |
|---|---|---|
| Where the balance lies | the wallet's own addresses: NEAR, NEAR Intents, EVM, Solana, a confidential balance, venue accounts | the wallet contract: a NEAR account, with its NEAR and its balance inside NEAR Intents |
| Who signs a move | the enclave, within the owner's policy | the agent's key and the enclave's key; the wallet contract verifies both |
| What the agent holds | an API key (`wk_…`); no private key | its own Ed25519 key, and the API key of its working account |
| Cost of a move | the operation's own cost; nothing is added per operation | one NEAR transaction to the wallet contract per move, with its gas, paid by the working account |
| Operations | every wallet operation: transfers, calls, swaps, withdrawals, limit orders, confidential intents, message and transaction signing on NEAR, EVM and Solana, connectors | NEAR transfer, contract call, transfer inside NEAR Intents, swap and withdrawal to another chain through 1Click, withdrawal to NEAR |
| What the owner does at setup | nothing is required; a policy and the registration for the owner's exit are the owner's choice | registers for the owner's exit, installs the wallet contract on an account, stores a policy |
| The policy | judged in the enclave before it signs | judged in the enclave before it signs its half; the agent's half is required as well |
| Leaving | the owner's exit yields the wallet's keys | the owner's exit yields the enclave's key of the wallet contract; the owner derives the agent's key with their own signature and signs for both sides |

What on-chain custody adds:

- The chain itself requires both signatures for anything to leave the wallet
  contract.
- The policy engine cannot move those funds by itself: the enclave's key is
  one of two.
- The owner can leave and sign for both sides, with no OutLayer service
  ([section 10](#10-leaving-with-a-wallet-contract)).

What it costs:

- A NEAR transaction and its gas for every move.
- A signature made on the agent's side, with a key the agent keeps.
- A setup by the owner.
- A narrower set of operations; the rest run from the working account.

Choose on-chain custody when the owner wants that rule held by the chain for
the agent's main balance. An agent that needs every operation, no key of its
own and no transaction per operation uses its OutLayer wallet alone.

On-chain custody is for a wallet with an owner: an account registered for the
owner's exit in the keystore DAO contract ([OWNER_EXIT.md](OWNER_EXIT.md)). Any
other wallet is refused with `400 bad_request` on every route below.

## 2. Who holds what

| Party | Holds | Alone it can |
|---|---|---|
| Agent | its Ed25519 key: it signs the agent's HTTPS requests and the agent's half of every move out of the wallet contract | move nothing |
| Enclave (Intel TDX) | nothing at rest; it derives its key for a wallet contract when it signs | move nothing out of the wallet contract |
| Owner account | the right to store the policy, approve, freeze and start an exit | move nothing out of the wallet contract before an exit completes |
| Wallet contract | the agent's main balance; the pair of public keys in its state | nothing: it executes a request that carries both signatures |
| The wallet contract account's own NEAR access keys | one key of the owner's by default; none, if the owner removed them at setup | everything on the account, past both signatures and past the policy |
| The agent's OutLayer wallet (working account) | a key in the enclave, as every OutLayer wallet | relay a transaction and pay its gas; hold what the agent took out to work with |
| NEAR MPC | the root the enclave's secrets come from, in threshold shares between its nodes | release a key to the account the chain names; move nothing in a wallet contract |
| Keystore DAO contract | owner records and the escrow of each owner's master | nothing: it holds ciphertexts it cannot open |

## 3. The two keys

| Value | Where it comes from | Where it lives |
|---|---|---|
| Enclave's key | the Ed25519 key whose seed is `HMAC-SHA256(owner master, "wallet-contract:{wallet_id}")` | nowhere; the enclave derives it when it signs |
| Agent's key | an Ed25519 key whose seed is `HMAC-SHA256(key = "outlayer/agent-key/v1", signature ‖ message)`, where `signature` is the owner key's NEP-413 signature over a fixed message that names the owner account and the wallet | the agent's machine; the owner derives it again by the same signature |
| Wallet contract's public key | the pair `agent ‖ tee` of the two public keys | the contract's state, written by `w_init` in the installing transaction |
| A request's proof | two Ed25519 signatures over the request's canonical hash, each under its own role prefix | in the transaction |

- **The enclave's key is a function of the owner's master and the wallet's
  id.** Nothing per wallet is stored in the enclave. The owner's master leaves
  with the owner's exit, and the enclave's key with it.
- **The agent's key needs no backup.** Ed25519 signatures are deterministic,
  so the owner's wallet makes the same signature over the same message, and
  the same key follows. Whoever is given that signature holds the agent's key:
  the message says so and names the one site that asks for it.
- **The link between a wallet and its wallet contract is checked on chain.**
  The enclave's key comes from the wallet's id, and the contract's state holds
  that key: a wrong id derives a key that is not in the contract.
- **A signature of one role is never valid for the other.** Each half is made
  under its own prefix, and a signature the agent makes over an HTTPS request
  is in a third byte format. A pair with equal keys is refused by the contract.
- **The enclave signs one shape of request, and never one it is given.** It
  builds every request itself from the operation the agent signed: one
  promise to another account, with one function call or one transfer. No
  route asks for the wallet contract's own operations (adding or removing an
  extension, switching signatures off), for a second promise, or for a
  request to sign as it is; such a body is refused as not an operation. This
  is the guarantee the rest stands on: an extension added under the two
  signatures could move everything the contract holds with neither.
- **A wallet contract has no extension.** An extension has full control of a
  wallet contract, so the enclave signs for no wallet contract that has one:
  the second line behind the one above.
- **A build the DAO approved, by its code hash.** The account uses a global
  contract by its code hash, so the installing transaction carries no code.
  The enclave reads the account's code hash before every signature and signs
  only for a build on the keystore DAO's list (`ApproveWalletContract`, a vote
  with the DAO's delay). An account stays on the build it was installed with,
  so a later build is approved beside the earlier one. The published build is
  `651XC7DH8J4Xczf8JKXH9pyveBY8ZuNCfy5HZ3SvuSiL`.

## 4. Setup

The agent opens a setup and hands its owner a link; the owner finishes it on
the site; the agent collects its key. The agent and the owner do not meet, and
the API carries between them a token and a sealed key it cannot read.

| Step | Who | What |
|---|---|---|
| 1 | Agent | makes a one-time X25519 key and opens a setup: `POST /wallet/v1/contract/setup`; gives its owner the link `https://app.outlayer.ai/wallet/custody#setup=<token>` |
| 2 | Owner | opens the link and connects the owner account; the page shows the owner, the agent's OutLayer wallet, the enclave's key for it and the network |
| 3 | Owner | chooses the account and what happens to the account's own keys (below) |
| 4 | Owner | signs one message with the owner key; the page turns the signature into the agent's key and shows the pair the contract will require |
| 5 | Owner | signs one plain transaction: the creation of the sub-account, or one key added to their own account. The page then installs the wallet contract on the account with the pair |
| 6 | Owner | hands the agent its key: the page seals it to the agent's one-time key and names the account, `POST /wallet/v1/contract/setup/owner` |
| 7 | Owner | stores a policy for the wallet; the enclave signs for a wallet contract only under a policy its owner stored |
| 8 | Agent | collects the account and its key: `GET /wallet/v1/contract/setup` |

Every signature on the page is behind a button whose label says what it does.
A refused wallet leaves the page on the same step.

### The account

| Choice | What happens |
|---|---|
| A sub-account of the owner's, `<name>.<owner>` (the page offers `agent`) | The owner's wallet creates it with 0.5 NEAR for its storage, the owner's key and a key the page holds for the installing transaction alone. The page then sends the account's own transaction: the global contract by its hash, `w_init` with the pair, and the removal of the page's key |
| The owner account itself | The owner's wallet adds one full-access key the page holds for the installing transaction alone: made in the tab, stored nowhere. The page then sends the same transaction as for a sub-account, which removes that key. The owner's key stays on the account and acts on it directly |

The owner's wallet signs nothing but an account creation, a transfer and added
keys, which every wallet signs. Installing is one transaction of the account
itself, signed by the page's key: `UseGlobalContract` by the code hash, then
`w_init(public_key)` with 1 yoctoNEAR attached, then the removal of the page's
key. A page closed between the two leaves that key on the account with nobody
holding it; the owner removes it in their wallet. OutLayer
neither creates the account nor computes its address. An account that was
installed by other means is named with `PUT /wallet/v1/contract`; it is taken
under the same check.

### The account's own access keys

A NEAR account's access key acts on the account directly: it moves the balance
and replaces the code with no signature of the agent or of the enclave, and no
policy or lock applies to it. The page states this and gives the choice for a
sub-account:

| Choice | What it means |
|---|---|
| Keep the owner's key on it (the default) | The owner acts on the account at any time with their own wallet. Whoever holds that key moves everything on the account at once, and no policy applies to it |
| Remove every key from it | Nothing moves without the agent's signature and the enclave's. The owner alone acts on it only through the owner's exit, after its window. It cannot be undone |

With the owner account itself as the agent's account there is no choice: the
owner's key stays, since the account needs it to store a policy, to approve
and to leave. The agent then acts as the owner's account toward every contract
its policy lets it call: what that account may do there, a vote in a DAO
included, the agent does in its name. Calls to OutLayer's own contracts are
refused, so the agent cannot store the policy it is held to.

A key registered for an account in NEAR Intents is an access key for what the
account holds there: it signs intents for the account with no signature of the
agent or of the enclave. A sub-account the setup creates has none. An owner
account that has used NEAR Intents has its own, as it has its NEAR key.

While the owner holds a key of the account, the setup is undone from the
owner's own wallet: another contract deployed on the account, or the account
deleted.

### Routes of the setup

`POST /wallet/v1/contract/setup` — wallet API key.

```json
{ "recipient_public_key": "<the agent's one-time X25519 public key, 32 bytes in lowercase hex>" }
```

```json
{ "token": "<64 hex characters>", "expires_at": "2026-11-27T12:00:00Z" }
```

The token is valid for 24 hours and ends when the setup is finished. Whoever
holds it can name this wallet's wallet contract once: the owner's account, a
sub-account of it, or the `0s` address of a fresh wallet contract on a build
the keystore DAO approved; in every case the account is taken only when its
pair on chain holds this wallet's enclave key. A `0s` contract can be made by
anyone with any agent key beside the wallet's public enclave key, so a holder
of the token who finishes first can name one with an agent key of their own
and act as the agent, within the owner's policy, until the owner finishes a
new setup, which replaces it. The link carries the token in its fragment,
which the browser sends to no server, and a spent token says it was spent. A
wallet has one setup: opening again issues another token for another one-time
key, ends the earlier token, and discards a sealed key that was not collected.

`GET /wallet/v1/contract/setup/owner` — the token is the only credential, sent as
`Authorization: Bearer <token>` and never in a URL of the API.

```json
{
  "wallet_id": "…",
  "owner": "alice.near",
  "tee_public_key": "<32 bytes in hex>",
  "recipient_public_key": "<32 bytes in hex>",
  "agent_key_request": {
    "message": "This signature is the key of your OutLayer agent. Sign it only on app.outlayer.ai, when you set up or recover an agent.\nOwner: alice.near\nWallet: …",
    "recipient": "outlayer-agent-key",
    "nonce_base64": "b3V0bGF5ZXIvYWdlbnQta2V5L3YxL25vbmNlAAAAAAA="
  }
}
```

The page computes the message itself and signs only when the API's request
equals it. A token that is unknown or expired, or that a later setup of the
wallet superseded, answers `404 request_not_found`.

`POST /wallet/v1/contract/setup/owner` — the token is the only credential, sent the same way.

```json
{ "account_id": "agent.alice.near", "sealed_agent_key": "<base64>" }
```

```json
{ "account_id": "agent.alice.near", "agent_public_key": "<32 bytes in hex>" }
```

The account's pair is read from the chain (`w_public_key`). It is refused with
`400 bad_request` when the account is neither the owner's nor a sub-account of
it, when it does not answer with a pair of keys or the pair's second half is
not this wallet's enclave key; with `409 conflict` when the account is another
wallet's wallet contract; and with `422 chain_refused` when the chain has no
such account, contract or method.

`GET /wallet/v1/contract/setup` — wallet API key.

```json
{ "wallet_id": "…", "done": false }
```

```json
{
  "wallet_id": "…",
  "done": true,
  "account_id": "agent.alice.near",
  "agent_public_key": "<32 bytes in hex>",
  "sealed_agent_key": "<base64>"
}
```

The agent opens the sealed key with the private half of its one-time key and
checks that the public key of what it opened is `agent_public_key`.
`404 request_not_found` when the wallet has opened no setup.

The same record without the setup link:

| Route | Does |
|---|---|
| `GET /wallet/v1/contract/key` | the enclave's public key of this wallet's wallet contract: `{ "tee_public_key": "<hex>" }` |
| `PUT /wallet/v1/contract` | names the account, `{ "account_id": "…" }`; reads its pair from the chain. Naming the same account again reads the pair again; an account that is another wallet's is `409` |
| `GET /wallet/v1/contract` | the recorded account and the agent's public key; `404 request_not_found` when the wallet has none |

### The sealed key

The agent's 32-byte seed is sealed to the agent's one-time X25519 key:

| Part | Bytes |
|---|---|
| format | `0x02` |
| one-time public key of the sealing side | 32 |
| AES-256-GCM ciphertext of the seed, with its tag | 48 |

The AES key is `HKDF-SHA256(shared secret, salt = empty, info = "outlayer:encryption-keys:v1:seal:kdf" ‖ one-time public key ‖ recipient public key)`,
where the shared secret is X25519 of the two keys. The nonce is twelve zero
bytes; the additional data is `outlayer:wallet-contract:agent-key:{wallet_id}`,
so a sealed key opens for its wallet only.

## 5. An operation

The agent asks for an operation in the words every wallet uses: a transfer, a
call, a swap, a withdrawal. The enclave judges that operation by the policy,
then builds the wallet contract's request for it. Nothing the agent supplies
is decoded or trusted as a request.

| Step | Who | What |
|---|---|---|
| 1 | Agent | sends the operation, signed by its key, under an id of its own choice: `POST /wallet/contract/v1/operations` |
| 2 | Enclave | reads the wallet contract from the chain: its code hash, its pair of keys, that it has no extension and accepts signatures; verifies the request against the agent's key in the pair |
| 3 | Enclave | reads the policy and checks that the owner account stored it; evaluates the operation; refuses here if the policy does; requires the approvers' signatures here if the policy asks for them |
| 4 | Enclave | builds the request, hashes it, signs its half |
| 5 | Agent | receives the request and the enclave's half; checks that the request is the operation it asked for; signs its half |
| 6 | Working account | relays `w_execute_signed(msg, proof)` from the wallet's own NEAR account and pays the gas: `POST /wallet/contract/v1/operations/{id}/relay` |
| 7 | Wallet contract | checks that signatures are allowed, the chain id, the signer id, the nonce inside its validity window, and both signatures; executes |

- **The agent signs last.** Its signature under a move exists only for a move
  the policy and the approvers have already passed. A refused or a waiting
  operation leaves no half of a move anywhere.
- **The agent checks the request.** The enclave's half is over a request the
  enclave built. Before adding its own half the agent compares the request
  with the operation it asked for: the signer, the receiver, the method, the
  arguments and the amounts. With its half added the wallet contract executes
  the request, so the agent's check is what makes its signature mean the
  operation it asked for.
- **Replay** is the wallet contract's own protection: a nonce per request,
  accepted once within the request's validity of ten minutes.
- **The operation is an object with an id.** The id is the agent's idempotency
  key: 1 to 64 characters of letters, digits, `-` and `_`. Asking again under
  the same id continues the same operation; the same id with another content
  is refused with `409 conflict`.
- **Nothing is repaired or retried on the agent's behalf.** A request off this
  path is refused, or the operation is closed with its reason.

### Operations

Amounts are decimal strings in the smallest unit: yoctoNEAR for NEAR, the
token's own for a token. A token is its id inside NEAR Intents
(`nep141:<account>`).

| `kind` | Fields | The wallet contract's request |
|---|---|---|
| `transfer` | `to`, `amount` | a transfer of NEAR to `to` |
| `call` | `to`, `method`, `args_base64`, `gas`, `deposit` | a function call on `to` with the exact gas, at most 250 Tgas |
| `intents_transfer` | `to`, `amount`, `token` | `mt_transfer` on the Intents contract to `to`'s balance there |
| `withdraw` | `to`, `amount`, `token` | `ft_withdraw` on the Intents contract: a NEP-141 token to the NEAR account `to` |
| `swap` | `token_in`, `amount_in`, `token_out`, `min_out` | `mt_transfer` of the input to the deposit address of a 1Click quote whose recipient and refund address are the wallet contract inside NEAR Intents |
| `cross_chain_withdraw` | `to`, `amount`, `token`, `chain` | `mt_transfer` of the input to the deposit address of a 1Click quote whose recipient is `to` on `chain` and whose refund address is the wallet contract |

- A `call` to a NEAR Intents contract, to the keystore DAO contract or to the
  OutLayer contract, and a call of a method whose name starts with
  `w_execute_`, are refused. A wallet contract sends no request to itself.
- NEAR Intents is on mainnet only: `intents_transfer`, `withdraw`, `swap` and
  `cross_chain_withdraw` are refused on testnet.
- The result of a swap arrives in the wallet contract's balance inside NEAR
  Intents, and so does a refund. A 1Click quote waits ten minutes for its
  input; an input that arrives later is returned by 1Click to the wallet
  contract. A swap is refused with `400 below_min_amount_out` when the quote
  guarantees less than `min_out`.
- Every other kind of wallet operation is refused with `400 bad_request` and
  runs from the working account
  ([section 8](#8-what-lies-in-the-wallet-contract-and-what-stays-on-the-working-account)).

### Statuses

| `status` | Meaning | What the agent does |
|---|---|---|
| `pending_approval` | the policy asks for approvers; `approval_id` names the vote | waits, then asks again under the same id with the same operation |
| `awaiting_signature` | prepared and counted; `message` and `tee_half` are present | checks `message`, signs its half, relays |
| `relayed` | the transaction `tx_hash` was sent and its outcome is not recorded | reads the operation; the read settles it |
| `success` | the request executed on chain. For a swap or a withdrawal to another chain it says the input reached 1Click's deposit address; `route_status` on a read follows the route | — |
| `failed` | the chain refused; `result` carries the chain's failure | reads the failure; the same thing again is another operation under another id |
| `closed` | ended with nothing sent, for `reason`: the vote was rejected or expired, an approval was not used within its 24 hours, a prepared request was not relayed within ten minutes, its transaction never reached the chain in that time, or the node refused it three times | reads the reason; the same thing again is another operation under another id |

### The agent's signed request

The operation routes take no API key. Each request carries four headers:

| Header | Value |
|---|---|
| `x-agent-account` | the wallet contract's account |
| `x-agent-timestamp` | Unix seconds, within 120 seconds of the server's clock |
| `x-agent-nonce` | 16 bytes in lowercase hex, the agent's choice; each request is taken once |
| `x-agent-signature` | 64 bytes in lowercase hex: the agent key's Ed25519 signature |

The signature covers the method, the path and the body
([section 12](#12-byte-formats)), so a request signed for one route is not
taken by another. A request not signed by the agent's key of the wallet
contract it names, or with a timestamp outside the window, answers
`401 invalid_signature`; so does an account that is no wallet's wallet
contract. A nonce seen before answers `409 conflict`.

### `POST /wallet/contract/v1/operations`

```json
{ "id": "pay-1", "op": { "kind": "transfer", "to": "bob.near", "amount": "1000000000000000000000000" } }
```

```json
{
  "id": "pay-1",
  "status": "awaiting_signature",
  "request_hash": "<sha256 of the operation's canonical JSON, hex>",
  "message": {
    "chain_id": "mainnet",
    "signer_id": "agent.alice.near",
    "nonce": 7,
    "created_at_ns": "1795000000000000000",
    "promise": {
      "receiver_id": "bob.near",
      "action": { "action": "transfer", "amount": "1000000000000000000000000" }
    }
  },
  "tee_half": "<64 bytes in hex>"
}
```

`request_hash` is the hash of the operation: what approvers sign, and what a
later request under the same id is compared with. It is not the hash of
`message`. A swap or a withdrawal to another chain also carries `quote`:
`amount_in`, `amount_out`, `min_amount_out`, `deadline`, `time_estimate`.

| Refusal | Meaning |
|---|---|
| `400 bad_request` | a header is missing or malformed, the body is not an operation, the `id` is not valid, the kind is not one a wallet contract does, or a `call`'s `args_base64` is longer than 65,536 characters |
| `400 insufficient_balance` | a swap or a withdrawal to another chain sends more than the wallet contract holds of the token inside NEAR Intents; checked before any quote |
| `400 below_min_amount_out`, `upstream_rejected`, `no_liquidity`, `unsupported_token`, `unsupported_chain` | what 1Click answered to the quote |
| `401 invalid_signature` | the request is not the agent's |
| `403 policy_denied` | the policy, or the enclave judging the same operation again, refuses it; `message` says why |
| `403 wallet_frozen` | the wallet is frozen |
| `403 wallet_contract_refused` | the enclave does not serve the account as this wallet's wallet contract: it runs no approved build, has an extension, has signatures switched off, or its pair does not hold this wallet's key; `message` says which |
| `409 conflict` | the nonce was taken, or the `id` was used for another content |
| `409 wallet_busy` | another operation is using this wallet; one operation of a wallet runs at a time |
| `409 conflict` (votes) | 20 operations of this wallet already wait for the approvers; one is decided or closes before another is asked for |
| `429 rate_limited` | too many quotes for this wallet; try later |
| `429 operation_limit_reached` | the wallet's counted ceiling on operations is reached |

A refusal creates no operation under the id.

### `POST /wallet/contract/v1/operations/{id}/relay`

```json
{ "agent_half": "<64 bytes in hex>" }
```

The half is verified against the agent's key and joined with the enclave's.
The enclave reads the wallet contract from the chain again, verifies the proof
for the request, and signs the transaction with the wallet's own NEAR key: one
call of `w_execute_signed` on the wallet contract with 300 Tgas and no deposit;
unused gas returns to the working account. The answer is the operation as the
chain settled it: `success`, or `failed` with the chain's failure in `result`.
A transaction whose outcome did not come back leaves the operation `relayed`
with its `tx_hash`.

An operation that is not `awaiting_signature` is answered as it stands, and
nothing is sent. An `agent_half` that is not the agent's signature over this
operation's request answers `401 invalid_signature`.

### `GET /wallet/contract/v1/operations/{id}`

Where the operation stands. Signed over the method `GET`, the path and an
empty body. A `relayed` operation is looked up on chain and answered as
`success` or `failed` once the chain has it. `404 request_not_found` when the
wallet contract has no operation under the id.

A wallet contract's operation is not a row under `/wallet/v1/requests`.

## 6. Approvals

The policy's approval rules apply to a wallet contract's operation as they do
to the same kind of operation of any wallet: M-of-N approvers over one exact
operation, with amounts below the policy's threshold passing without one.

- An operation that needs approvers is answered `pending_approval` with
  `approval_id`. The vote is read and cast on like any other
  (`GET /wallet/v1/approval/{id}`, `POST /wallet/v1/approve/{id}`); its type
  is `wallet_contract`, and it lives 24 hours: the agent asks again within
  them, voted or not, or the operation is closed. The policy's `webhook_url` receives `approval_needed`
  with `operation_id` (the agent's id), `approval_id`, `type` and `required`.
- **Each change of status is told to the owner's webhook.** When the policy
  names a `webhook_url`, it receives `operation_updated` with `operation_id`
  (the agent's id), `type` (`wallet_contract`), `status`, `tx_hash` and
  `reason` as an operation becomes `awaiting_signature`, `relayed`, `success`,
  `failed` or `closed`. The address is the one the policy named when the
  operation was asked.
- **What is under way.** `GET /wallet/contract/v1/operations`, signed like
  every other request, lists the operations that are not over (waiting for
  the approvers, for the agent's half, or for the chain), newest first, at
  most 100: the place an agent that restarted picks up from.
- **An approval starts nothing.** Once the approvers have voted, the agent
  sends the same request again under the same id. The votes go to the enclave
  with it, the enclave verifies them over the operation's hash, and the
  operation is prepared. A vote that ended any other way closes the operation
  with the reason.
- An approval covers one exact operation, which still has to fit the policy.

## 7. Limits and usage

- **The limits are the wallet's.** The policy's limits per transaction, hour,
  day and month count one set of counters for the working account and the
  wallet contract together.
- **Usage is counted when the request is prepared**, with the answer that
  hands out the enclave's half: from that moment the agent holds everything it
  needs to execute the request. It is not given back: not when the request is
  never relayed, and not when it fails on chain.
- A `transfer` counts its `amount` and a `call` its `deposit` under `native`;
  every other kind counts its input amount under its token.
- **A prepared request that is not relayed within ten minutes is closed.** The
  wallet contract accepts a request for ten minutes from its `created_at_ns`.
- **A freeze stops new requests, not the one already prepared.** A prepared
  request carries the enclave's half, and the wallet contract accepts it with
  the agent's half until its ten minutes end. One operation runs at a time, so that
  is one request at most.
- One operation of a wallet runs at a time (`409 wallet_busy`), so the limits
  are counted correctly.
- The working account pays the gas of every relay, and keeps **0.5 NEAR** for
  it. Before a relay runs, the node checks that the working account could pay
  the 300 Tgas the relay attaches at the highest gas price the transaction can
  meet, ten times the current one: 0.3 NEAR at today's 0.0001 NEAR per Tgas, on
  both networks. That 0.3 NEAR is checked, not spent. A relay of a transfer
  burns about 0.0004 NEAR; a call burns more, at most 0.03 NEAR when it uses all
  300 Tgas. With 0.5 NEAR the 0.2 above the check pays for some 500 transfers,
  and for at least six relays that burn everything. Top the account up to 0.5
  once it is under 0.35 NEAR, rather than at a refusal: a relay the account
  cannot cover answers `402 wallet_underfunded` with its balance and the cost.

## 8. What lies in the wallet contract and what stays on the working account

Two signatures guard what lies in the wallet contract. Work that needs a key
that signs by itself runs from the agent's OutLayer wallet, whose key is in
the enclave like every OutLayer wallet's:

| | In the wallet contract | On the working account |
|---|---|---|
| What | the main balance: NEAR on the account and tokens inside NEAR Intents | a confidential balance; a venue's trading account (Hyperliquid, Polymarket); a balance kept for limit orders; NEAR for gas |
| Signed by | the agent and the enclave | the enclave, within the policy |
| Asked for with | the agent's signed request | the wallet's API key |

Funds reach the working account by a move out of the wallet contract, under
both signatures, and return to the wallet contract by an ordinary operation of
the working account. How much stays on the working account is the agent's
choice.

| Where | How |
|---|---|
| NEAR | the wallet contract's account: transfers, contract calls |
| NEAR Intents | the wallet contract's account holds the balance; a swap is a transfer to a 1Click quote's deposit address and returns to the wallet contract |
| Other chains | withdrawals through 1Click, from the wallet contract's balance inside NEAR Intents |
| Confidential intents, limit orders | from the working account |
| Hyperliquid, Polymarket | connectors: the venue's trading account belongs to the working account |

## 9. Running a program as the wallet contract's account

A program run in OutLayer acts as the account in `NEAR_SENDER_ID`. With
`use_bound_identity` set on a call, that account is the caller's wallet
contract instead of the wallet's own NEAR account. A wallet with an active
binding (Agent Connect) runs as its bound account, as before: the wallet
contract is the name of a wallet that has no active binding. The flag is on both ways of
starting a run: the body of the HTTPS call and the arguments of
`request_execution` on chain. It is off by default and is the caller's choice
on each call.

- Billing does not follow the name: `NEAR_USER_ACCOUNT_ID` stays the account
  that paid.
- Over HTTPS the wallet is the one the paying key names. A call whose key
  names no wallet, or whose wallet has neither an active binding nor a wallet contract, is refused with
  `409 no_bound_identity` before it is priced or charged. On chain the wallet
  is the one whose NEAR account sent the transaction.
- Before the program is given the name, the worker asks the enclave. The
  enclave confirms that the caller is the NEAR account of the wallet and that
  the claimed account, read from the chain, is a wallet contract with that
  wallet's enclave key in its pair. A job that fails this is refused; it is
  never run under the caller's own name in its place.

The flag changes a name. It gives the program no signature of the wallet
contract: a move out of the wallet contract is an operation of
[section 5](#5-an-operation).

## 10. Leaving with a wallet contract

The owner's exit ([OWNER_EXIT.md](OWNER_EXIT.md)) yields the owner's master.
The enclave's key of every wallet contract of that owner is derived under it,
so it leaves with the master. The agent's key comes from the owner's own
signature. After the exit the owner holds both keys of each wallet contract.

| Step | Who | Needs |
|---|---|---|
| Start, wait, claim | the owner account, on the keystore DAO contract | NEAR, NEAR MPC |
| Derive the enclave's key | the owner, from the master | — |
| Derive the agent's key | the owner's wallet repeats the signature of the setup | — |
| Sign and send | a request to the wallet contract with both halves; any NEAR account relays it | the chain's RPC |

`customer-recovery wallet-contract` does the last three steps: it prints the
agent-key request for the owner key to sign, derives the pair, and builds a
request with both halves as the arguments of `w_execute_signed` together with
the near-cli command that sends it. It talks to no service and to no chain.
The commands and the moves they build:
[scripts/customer-recovery/README.md](../scripts/customer-recovery/README.md#a-wallet-contract-after-an-exit).

- The registration for the exit comes before the wallet contract: on-chain
  custody is refused for a wallet without an owner, so no wallet contract is
  set up without a way out.
- The pair of a wallet contract is set once, when it is installed, and both
  keys are derived for the owner and the wallet: the same wallet always has
  the same pair. Another agent key is another agent: a new OutLayer wallet
  with a wallet contract on another account. The owner moves the assets there
  with their key of the old account, or through the exit where the keys were
  removed.
- An owner who keeps a key on the account acts on it at any time with that
  key, without an exit.

## 11. What a compromise reaches

| What is compromised | What it reaches |
|---|---|
| The enclave (memory read) | the enclave's key. No signature of the agent, so no move out of a wallet contract; and no move signed by the agent that the policy did not pass, since the agent signs last. What lies on the working account is under the enclave's key |
| OutLayer's governance: a hostile build, a hostile upgrade of OutLayer's own contracts | the enclave's key, and still no move out of a wallet contract without the agent's signature. No contract OutLayer can change is on the path of the funds in a wallet contract |
| The coordinator (the API in front of the enclave) | no move of its own and no request in the agent's name: the enclave verifies the agent's signature and reads the wallet contract itself. The coordinator supplies the 1Click deposit address, the request's nonce and the counters of what was spent; the agent checks the request before it signs |
| The agent's machine | the agent's key. Every operation still passes the enclave's policy; the owner freezes the wallet, sets up another agent on another account and moves the assets there |
| A prompt injection into the agent | an operation request, which the enclave judges by the policy |
| The owner account's key | the agent's key, by the setup's signature. With a locked policy: what the policy allows as it stands, since a change of policy and an exit both need the approvers. Without a lock the owner's key is the whole authority |
| An access key of the wallet contract's account, where the owner kept one | everything on that account, at once: the key is above the contract, and neither the policy nor its lock applies |
| A setup token | the right to name this wallet's wallet contract once, within 24 hours: the owner's account, a sub-account of it, or the `0s` address of a fresh wallet contract on an approved build, always with this wallet's enclave key in its pair. A holder who finishes first with a `0s` contract of their own agent key acts as the agent, within the owner's policy, until the owner finishes a new setup. The token ends when the setup is finished and says so after. The sealed agent key opens with the agent's one-time key alone |
| NEAR MPC | the enclave's key, through the master; not the agent's, which comes from the owner's own signature. No move out of a wallet contract |

## 12. Byte formats

One implementation of each format is in the `custody-core` crate of
[shared-tee-helpers](https://github.com/out-layer/shared-tee-helpers); the
enclave, the API and the owner's recovery tool build on it. Its `vectors/`
directory holds test vectors: `messages.json`, `halves.json`, `keys.json`,
`agent_request.json`. The contract's two-key standard
(`contracts/wallet/signatures/two-key`) carries the same `halves.json`. An
implementation that signs for a wallet contract checks itself against these
files.

### The request and its hash

`hash = SHA3-256("NEAR_WALLET_CONTRACT/V1" ‖ borsh(request))`

The request is one promise to another account with one action. Its Borsh
encoding, in the wallet contract's own layout:

| Field | Encoding |
|---|---|
| `pay_for_gas` | `0x00` |
| `chain_id` | string: `mainnet` or `testnet` |
| `signer_id` | string: the wallet contract's account |
| `nonce` | `u32` |
| `created_at` | `u64`, nanoseconds since the Unix epoch |
| `timeout_secs` | `u32`, `600` |
| wallet operations | `u32` count, `0` |
| promises | `u32` count, `1` |
| `receiver_id` | string |
| `refund_to` | `0x00` (none) |
| actions | `u32` count, `1` |
| the action | function call: `0x02`, the method (string), the arguments (bytes), the deposit (`u128`), the gas (`u64`), the gas weight (`u64`, `0`). Transfer: `0x03`, the amount (`u128`) |

A Borsh string or byte array is its length as a little-endian `u32`, then the
bytes; integers are little-endian.

The API carries a request as JSON (`message`): `chain_id`, `signer_id`,
`nonce`, `created_at_ns` (a decimal string) and `promise` with `receiver_id`
and `action`. An action is `{ "action": "transfer", "amount" }` or
`{ "action": "function_call", "function_name", "args", "deposit", "gas" }`,
with `args` in base64 and the numbers as decimal strings. The contract's own
JSON form, the argument `msg` of `w_execute_signed`, is built from it by
`RequestMessage::to_json`.

### The two halves and the proof

| Value | Bytes |
|---|---|
| Agent's half | the agent key's Ed25519 signature over `"NEAR_WALLET_TWO_KEY/V1/AGENT" ‖ hash` |
| Enclave's half | the enclave key's Ed25519 signature over `"NEAR_WALLET_TWO_KEY/V1/TEE" ‖ hash` |
| Proof (`w_execute_signed(msg, proof)`) | `agent half ‖ enclave half`, 256 characters of lowercase hex |
| Public key (`w_public_key()`, `w_init(public_key)`) | `agent ‖ tee`, 128 characters of lowercase hex |

Any other form of the public key or of the proof is refused by the contract:
another length, an uppercase character, a separator. A pair of equal keys and
a key of low order are refused, at initialization and at verification.

### The agent's signed HTTPS request

The agent's key signs the ASCII text `OUTLAYER_AGENT_REQUEST/V1` followed by
the Borsh encoding of, in this order:

1. the account (string): the value of `x-agent-account`;
2. the method (string), in capitals: `POST` or `GET`;
3. the path (string), with its query, as sent;
4. the SHA-256 of the body as sent (32 bytes); of the empty string when there
   is no body;
5. the timestamp (`u64`): the value of `x-agent-timestamp`;
6. the nonce (16 bytes): the value of `x-agent-nonce`.

These bytes start with their own domain, so a signature over a request is
never valid as a half of a move.

### The agent's key

The owner's key signs, under NEP-413, the message

```text
This signature is the key of your OutLayer agent. Sign it only on app.outlayer.ai, when you set up or recover an agent.
Owner: {owner}
Wallet: {wallet_id}
```

for the recipient `outlayer-agent-key` with the 32-byte nonce
`outlayer/agent-key/v1/nonce` padded with five zero bytes. The agent key's
seed is `HMAC-SHA256(key = "outlayer/agent-key/v1", signature ‖ message)`.

## 13. Operator configuration

The keystore takes no setting for on-chain custody. The builds of the wallet
contract it signs for are the keystore DAO's list
(`get_approved_wallet_contracts`): a build is added by an
`ApproveWalletContract` vote and taken off by `RevokeWalletContract`, or at
once by the DAO's owner (`remove_approved_wallet_contract`). The DAO contract
that carries the list is upgraded before a keystore that reads it starts, and
the build is approved before the first setup.

The keystore's four routes take a coordinator or worker token, as every
keystore route that reads the chain or derives a key:

| Keystore route | Asked by | Does |
|---|---|---|
| `/wallet/contract/key` | coordinator | the enclave's public key of a wallet's wallet contract |
| `/wallet/contract/prepare` | coordinator | admits the wallet contract, verifies the agent's request, judges the operation by the owner's policy, builds the request and signs the enclave's half |
| `/wallet/contract/relay` | coordinator | admits the wallet contract, verifies the proof, signs the relaying transaction with the wallet's NEAR key |
| `/wallet/contract/identity` | worker | whether a caller's wallet is the one an account is the wallet contract of |

An account is admitted as a wallet's wallet contract when, as the chain
answers at the moment of the request, it runs an approved build, has no
extension, accepts signatures, and holds a pair whose second key is this
wallet's enclave key. The account's own access keys and its balance are the
owner's and are not looked at.
