# Owner exit: leaving with a wallet's keys through the keystore DAO

A wallet whose owner is a NEAR account registered in the keystore DAO contract can be
taken out of OutLayer by that owner: the owner ends up holding the keys, and needs no
OutLayer service to get them — only NEAR and the NEAR MPC network.

Two exits exist. They differ in what they yield and in who could ever take them away;
[EXITS.md](EXITS.md) sets them side by side with a wallet that has neither.

| | Owner exit (this document) | Vault exit ([LEAVING_OUTLAYER.md](LEAVING_OUTLAYER.md)) |
|---|---|---|
| Set up by | one transaction to the keystore DAO, a fee of 0.05 NEAR | deploying a vault contract on a sub-account, 1 NEAR kept on it |
| Yields | the wallets' keys | the wallets' keys and every secret bound to the vault |
| Can it be removed | by an upgrade of the DAO contract, which waits the governance delay after the vote that approves it | no: a vault's code is fixed |
| Wait | the owner's exit window, 24–48 h | the vault's exit window, 1–30 days |

An application that must be able to take its secrets out — a `PROTECTED_` secret, which is
generated in the TEE and never shown, included — binds them to a vault. An owner exit
leaves secrets where they are.

## How it works

The keystore derives the master of an owner inside the TEE from the default master and the
**owner path** `owner:{account}:{generation}`. Every wallet of the owner in that generation
derives its keys from that master. Nothing about an owner is fetched or kept across a
keystore restart.

What makes the master leave with its owner is its **escrow**: the master, sealed under a
key only NEAR MPC can produce — the CKD key for the owner path with the DAO contract as
predecessor — and stored in the DAO contract. The keystore writes it on the first use of a
generation, before the first address of a wallet is returned, so a wallet that exists has
an exit.

The DAO contract asks MPC for that key for two callers only: an approved keystore, until
the generation's escrow is stored, to write it; and the owner, after the exit window, to
open it. When the owner
claims the key the **generation** moves on by one. The keystore reads the owner's record
from the chain before every operation and stops serving the generation that left: its keys
are the owner's now.

The contract's methods, fees and timing: [keystore-dao-contract/README.md](../keystore-dao-contract/README.md#owner-exit).
The keystore's side and the escrow's format: [keystore-worker/README.md](../keystore-worker/README.md).

## Getting a wallet with an exit

The owner's registration is a transaction a person signs in a NEAR wallet. An agent cannot
make it, so an agent asks, the person signs, the agent checks:

1. The agent calls `POST /wallet/v1/exit-link` with `{}` or `{"seed": "…"}`. No auth. It
   answers `{api_key, link, expires_at}`. Nothing is stored; `link` carries the key's hash,
   the seed, the network and the expiry under the coordinator's MAC.
2. The agent gives its user `https://app.outlayer.ai/exit?link=<link>` and keeps `api_key`.
3. The user connects a NEAR wallet. The page shows what will happen — the registration fee,
   the exit window to choose, the account that becomes the owner, and that the agent
   holding this key will operate the wallet — and then two buttons, each named after what
   it asks of the wallet: a transaction that registers the account in the DAO (once per
   account), and a signature that creates the wallet.
4. The agent polls `GET /wallet/v1/address` with `api_key`: 401 until the user has finished,
   the address after.

A link creates a new wallet. If the owner already has a wallet with that seed, or the link
was used before, the answer is 409 and nothing is written: a link never adds a key to a
wallet that exists. A 409 is also the answer while the owner is claiming the keys of the
current generation: the wallet is created once the claim has settled.

A wallet in an owner's scope is deterministic: `wallet_id = f(account, seed, owner path)`.
With no seed in the link the owner's next free numbered seed is taken — `0`, `1`, `2`, ….

The policy of a wallet in an owner's scope is stored by the owner account and by no other:
the keystore signs a policy for that sender alone, and `403` for any other.

An agent that already works on a wallet without an owner can move to one with an exit: it
is a new wallet at a new address, the funds move by an ordinary transfer, and the venue
accounts of the old wallet (Hyperliquid, Polymarket) are opened again under the new one.

### The owner's own access

`Bearer near:` works for an owner's scope as it does for a vault's: the token carries
`"master": "owner"` and its signed message is `auth:<seed>:<timestamp>:@owner`. The
generation is the owner's current one, read from the DAO on every request — after an exit
the same `(account, seed)` is a new wallet at new addresses, in the next generation.

`GET /wallet/v1/address` reports `exit_owner: {account_id, generation}` for such a wallet.

## Locked policies

A policy with `approval.locked` changes only with its approvers' quorum. An exit would be
a way round it, so the owner's exit needs the same quorum:

- the owner names the same accounts and threshold in the DAO (`set_exit_approvers`) —
  the first set takes effect at once, every later change needs the quorum of the set in
  force;
- the keystore signs a locked policy for the owner's wallet only when the DAO's set equals
  the policy's;
- an approver votes on an exit with a transaction from their account (`approve_exit`,
  `reject_exit`); one reject ends that exit.

For such a wallet a locked policy is refused when an approver has no account id, an id is
not an account id exactly as written, an approver is pinned to a key, or there are more
than 16 approvers.

Approvers who are lost or refuse block the exit for good. Exit approvers are public on
chain. An owner whose wallets need different approver sets uses different accounts.

## Leaving

Before the exit: withdraw from Polymarket and Hyperliquid, and reclaim open payment
checks, while OutLayer does it for the wallet. After the exit their keys come from the
master too (`derive-wallet-key` below: the venues' EVM sub-keys
`connector.hyperliquid.trading` and `connector.polymarket.trading`, and the checks' NEAR
keys), but moving those funds then takes the venue's or NEAR Intents' own tools.

The tool is [`scripts/customer-recovery`](../scripts/customer-recovery/README.md). Pass the
owner's key in the environment, never on the command line.

```bash
export OWNER_PRIVATE_KEY='ed25519:…'          # a full-access key of the owner account
export MPC_PUBLIC_KEY='bls12381g2:…'          # MPC's key for CKD domain 2
C="--owner alice.near --dao dao.outlayer.near --rpc-url https://rpc.mainnet.fastnear.com"

customer-recovery owner-exit status   $C      # generation, window, approvers, a pending exit
customer-recovery owner-exit initiate $C      # attaches the exit fee; starts the window
# … the exit window passes; approvers vote if a set is in force …
customer-recovery owner-exit claim    $C --claim-file ~/.outlayer-recovery/alice.near.claim.json
```

`claim` writes the claim file — the one-time key MPC's answer is encrypted to, and the hash
of the claim transaction — before it sends the transaction, then reads the transaction's
result from the chain, opens the escrow from the DAO contract and prints `master_hex=…`.
A claim that returned the key is not made again, and the claim file is what opens it: keep it. A claim
never writes over a file that exists; each claim takes a new path.

`customer-recovery owner-exit open --claim-file …` reads the same result from the chain
again — after a claim whose own run was cut short, or later. An ordinary RPC node keeps a
transaction's result for a few days; after that `open` needs an archival RPC, and says so. If `claim` ends
without a master, run `open` on its file before anything else: the transaction may have
gone through.

A claim MPC did not answer changes nothing in the DAO: the generation stays, OutLayer keeps
serving it, and the claim is made again, with a new claim file, inside the claim window (7
days after the exit window ends on mainnet). If MPC answers such a claim after its own
timeout, the answer is in MPC's transaction and not in the claim's: the owner then may hold
the key of a generation OutLayer still serves, until the next claim moves the generation
on. An exit not claimed by then lapses and is started
again.

With the master, the wallets:

```bash
export CUSTOMER_RECOVERY_MASTER=<master_hex>
customer-recovery owner-exit wallets $C --generation 1
#   seed=0 wallet_id=… near_account=… on_chain=true
customer-recovery derive-wallet-key --wallet-id <wallet_id> --chain all
```

`derive-wallet-key --chain all` prints every key of the wallet: NEAR, EVM (one key for
every EVM network) and Solana, each with its address, public key and private key in the
form that chain's wallets import. `--sub-path <p>` (repeatable) adds an EVM sub-key, and
`--checks <n>` the keys of payment checks 0 to n−1. Without these flags it prints the NEAR
key alone. The seeds and formats: [LEAVING_OUTLAYER.md](LEAVING_OUTLAYER.md#b2-re-derive-each-wallets-keys).

`wallets` walks the numbered seeds from 0 and stops after five in a row with no NEAR
account on chain. A wallet that never held NEAR — used only on another chain, or never
funded — has no such account: it is not listed and counts toward the five. A wallet made with a named seed is found with
`customer-recovery compute-wallet-id --account-id alice.near --seed <seed> --vault-id owner:alice.near:1`.

## After the exit

- Every operation of the wallets of the generation left that needs their keys — an
  address, a signature, a transfer — answers 403 in OutLayer; the policy no longer
  applies; the keys are the owner's. The same 403 is answered while a claim is in flight
  — to a request by the owner's own `Bearer near:` signature the answer then is 409 — and
  ends if MPC does not answer the claim. This follows the generation in the DAO, which moves
  when the claim's callback sees MPC's answer.
- No payment key of the wallets of the generation left spends: not the nonce-0 key —
  its trial, sponsored or gift credit ends with the exit — and not a funded key. A call and
  a subscription bought with a key's balance answer `403` with `reason: "wallet_exited"`;
  the same while a claim is in flight (then with `terminal: false`), and `503` when the
  chain does not answer whether the wallet is still in custody. The run of an approved task
  answers nothing: the task fails `preparer_key_unavailable`, or `queue_unavailable` when
  that read fails. A call admitted before the exit settles as it would have. The money
  on a funded key is the wallet's, and the wallet's NEAR account — whose key
  `derive-wallet-key` gives — takes it back on chain: `outlayer login` with that account
  and key, `outlayer keys close <nonce>` (`close_payment_key`), and 24 hours later
  `outlayer keys claim <nonce>` (`claim_payment_key_refund`). A stablecoin balance
  deposited on the account comes back with the contract's `withdraw_balance`. Allowance,
  grants and trial credit are not refunded.
- The owner's next wallet is created in the next generation: a new wallet id, new
  addresses, its own escrow.
- Secrets are untouched. A project's secrets belong to the owner's account and its
  applications keep reading them. An agent's secret filed under a wallet that left stays on
  chain as ciphertext; its deletion is signed by the wallet's key, which the owner holds.

## Leaving with a wallet contract

An agent with on-chain custody keeps its main balance in a wallet contract: a NEAR account
that executes a request only under two signatures, the agent's key and the wallet's TEE
key. The TEE key is derived under the owner's master, with the root `wallet-contract:`, so
it leaves with the master. After the exit the owner derives both keys and acts on the
wallet contract alone with `customer-recovery wallet-contract`: it builds a request that
carries both signatures and prints the near-cli command that sends it. The tool talks to no
service and to no chain, and any NEAR account sends the call. The commands and the moves
they build: [scripts/customer-recovery/README.md](../scripts/customer-recovery/README.md#a-wallet-contract-after-an-exit).
The wallet contract, its two keys and what each party holds: [ON_CHAIN_CUSTODY.md](ON_CHAIN_CUSTODY.md).

## A wallet with an exit acts through no extension

A wallet's NEAR key leaves with the owner's master, and so would any right another account
gave that key. Before the exit the keystore signs nothing that uses such a right:

- No wallet signs a call to `w_execute_extension`, the method of an account with full
  control of a wallet contract. The call answers 403 `policy_denied` under any policy and
  under none.
- An owner's wallet signs no raw NEAR payload (`raw_sign` on `near`), whatever its policy
  lists: 32 bytes signed with the wallet's NEAR key are any NEAR transaction, this one
  included, and the keystore cannot read them. NEAR is signed through `call`, `transfer` and
  the intents operations, which the keystore reads.

An account can give a wallet's NEAR account rights over itself without OutLayer: an
extension that names the wallet's address is that account owner's own transaction, and
nothing here stops it. Before the exit the keystore still signs nothing of the wallet that
acts on such an account. After it, the wallet's key is the owner's, and so is whatever that
key may do on the account that named it. Do not give an account to the address of a wallet
whose keys can leave unless the account is the wallet owner's own.

## A wallet never calls the keystore DAO

The DAO takes whoever calls it for an owner. The keystore signs no call to the keystore DAO
(`dao.outlayer.near`, `dao.outlayer.testnet`) under any policy, with no capability that
opens it, and an operation of a wallet contract that calls it is refused as well. Every
exit call is a transaction the owner signs with the account's own key.

`sign-message` signs no message whose recipient has the form NEP-641 gives an account's
off-chain authorization (`<chain>: <account>[ -> …] @ <time>`, or the same without
` @ <time>`): such a signature is the account's authorization, given off chain, of itself
and of every account that named it an extension. A recipient that only looks like one —
`Login: alice` — is refused as well.

A keystore starts only under a DAO this rule names.

## What an owner should know

- The owner account's key is the root: whoever holds it — with the approvers' quorum, if a
  set is in force — gets the master after the exit window. Lowering the window takes effect
  only after the window in force has elapsed.
- Nothing notifies an owner of an exit started with their key. `owner-exit status` and the
  dashboard show a pending exit.
- An exit through the DAO can be removed by an upgrade of the DAO contract. An upgrade
  runs no earlier than the governance delay — 72 hours on mainnet — after the vote that
  approves it, and so does a proposal that shortens the delay. To leave ahead of one, the
  exit is started within `delay − exit window` of that vote: 48 hours with the default
  window.
- An exit yields keys, not safety from a bad release: after exiting on a governance alert,
  move the funds.
- The owner is an account name: whoever controls that name is the owner.
