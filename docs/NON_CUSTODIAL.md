# Custody model

Who holds the keys, and who can move the money.

## The test

Two questions decide whether a party is a custodian of someone else's funds:

1. Does it hold the private key?
2. Can it move the balance without the owner's own signature?

For OutLayer the first answer is that no private key exists anywhere a
person could reach it. The second answer is set by the wallet's policy,
which the owner writes and only the owner can change. This page states
precisely what each party can and cannot do, and how to configure a
wallet so that nothing moves without the owner signing it.

---

## 1. No one holds a private key

A wallet's private key is never generated, stored, or transmitted. It is
derived on demand inside an Intel TDX enclave:

```
master secret (from the NEAR MPC network, never leaves the enclave)
    └── HMAC-SHA256(master, "wallet:{wallet_id}:{chain}")  →  signing key
```

Four properties follow, and each is verifiable without trusting us:

| Property | How it is enforced |
|---|---|
| The master secret is issued by the NEAR MPC network, not by OutLayer | The keystore obtains it through a chain-key derivation call to the MPC contract. The MPC network holds threshold shares; no single node, and no OutLayer employee, can reconstruct it |
| Only attested code can obtain it | The keystore submits a TDX attestation quote on chain. The contract verifies the quote's signature chain up to Intel's certification service and checks the build's five measurements against the approved set. Only then does an on-chain DAO vote install the access key the keystore needs |
| The code cannot export a key | The enclave derives and signs. There is no endpoint, log path, or debug facility that emits key material. The image is measured, so the code that runs is the code that was approved |
| The infrastructure operator cannot read memory | TDX encrypts enclave memory against the host. An operator can stop a machine; it cannot look inside one |

The consequence for the custody test: there is no key for OutLayer to
hand over, seize, or lose, and no version of our software that behaves
differently without a new on-chain registration that anyone can see.

## 2. Every master secret is issued on chain

Keys and secrets are derived from a master secret, so the question that
matters is how a master comes to exist inside an enclave. It cannot
happen quietly. Each acquisition is a public NEAR transaction:

| Master | Who signs the request | Where it is visible |
|---|---|---|
| Shared root (default wallets) | the keystore's access key on the DAO contract, calling `request_key` | a public transaction. That access key exists only because DAO members voted to install it after the contract verified the enclave's attestation quote |
| Per-customer vault master | the enclave's function-call key on **your own vault contract**, calling `request_master`, which proxies the call to the MPC contract | a public transaction **on your own account** — it appears in your vault's history, not only in ours |

Two things follow. The authority to obtain a master at all comes from an
on-chain vote on a verified attestation, so an unapproved build gets
nothing. And a customer running a vault does not have to take our word
for how often their root was derived: the transactions are on the
customer's own contract.

Serving is re-checked continuously, not just at issue time. Every signing
operation on a vault-scoped wallet re-reads on-chain state first — the
DAO's verified set, and whether the vault is still under enclave control
— even when the master is already in enclave memory. The moment a
customer finishes recovery, that check fails, the cached master is
evicted, and the keystore refuses to sign. The customer does not have to
ask us to stop.

To be precise about scope: deriving an individual wallet key and
decrypting an individual secret happen inside the enclave from the
master and do not each produce a transaction. What is on chain and
DAO-gated is which builds may hold a master and every event of one being
issued.

## 3. The state that governs your funds lives on chain

OutLayer is built so that our own servers are not part of anyone's trust
model. The things that decide what may happen to your money are contract
state, not rows in a database we control:

| What | Where it lives | Who can read it | Who can change it |
|---|---|---|---|
| Wallet policy | encrypted in the NEAR contract | only the enclave decrypts it | only its controller account |
| Freeze flag | the same contract entry | anyone | only the controller |
| Secrets | encrypted in the NEAR contract, bound to an owner and a profile | only the enclave decrypts them | their owner |
| Approved builds, keystore registrations | the DAO contract | anyone | DAO vote |
| Vault state, exit window, recovery status | your own vault contract | anyone | you, through the parent account |

What our database holds is operational: the job queue, usage counters,
webhook records, and the hash of an API key. None of it grants authority.
An attacker who owned that database entirely could disrupt service and
read operational metadata. They could not decrypt a policy, weaken one,
lift a spending limit, or produce a signature, because none of those are
decided there.

The enclave connects the two halves: it reads the encrypted policy
directly from the chain, decrypts it in memory the host cannot observe,
evaluates it, and only then signs. The rules are enforced by code you can
identify, over data you can read, with nothing trusted in between.

## 4. Nothing is signed outside the policy

Every signable action is expressed as a canonical operation, hashed, and
checked against the wallet's policy **inside the enclave** before a
signature exists.

The policy lives encrypted in a NEAR smart contract. Only the enclave can
decrypt it, so the rules cannot be read or edited by our operations team,
our database, or anyone who compromises our servers.

Two facts about the policy matter more than any other on this page:

- **The account that first stores a policy becomes its controller.** Only
  that account can update it, delete it, freeze the wallet, or unfreeze
  it. The signature we produce for a policy write is bound to the exact
  account that will send the transaction, so the controller cannot be set
  to someone else by mistake or by us.
- **A wallet with no policy is unrestricted.** Registration does not
  create rules. Until a policy is stored, whoever holds the API key can
  move the balance within the limits of the primitives enabled by
  default. Storing a policy is the act that creates the constraint.

The controller can also freeze the wallet by sending one transaction
directly to the contract. That path does not involve our API at all, so a
freeze works even if OutLayer is unreachable or uncooperative.

## 5. Making the owner's signature mandatory

A policy can name approvers and a threshold. When it does, every
fund-moving operation stops and waits:

```json
{
  "version": 1,
  "rules": { "limits": { "per_transaction": { "*": "..." } } },
  "approval": {
    "threshold": { "required": 1 },
    "approvers": [
      { "id": "customer.near", "role": "admin", "pubkey": "ed25519:<base58>" }
    ]
  }
}
```

With this policy in place:

- An API key can **propose** a transfer. The response is a pending
  approval, not a transaction.
- The approver signs `approve:{approval_id}:{wallet_pubkey}:{request_hash}`
  as a NEP-413 message with their own wallet.
- The enclave re-derives `request_hash` from the stored canonical
  operation and verifies the signature itself. Our coordinator transports
  the signature; it cannot forge one, and it cannot re-bind a signature to
  a different operation.
- Only then does a signature over the transaction come into existence.

So the owner's signature is not a courtesy step in a user interface. It
is a precondition enforced by measured code, using a public key pinned in
the on-chain policy.

## 6. The four configurations

| Configuration | Who holds the API credential | Who can move funds | What OutLayer can do alone |
|---|---|---|---|
| **Default, no policy** | whoever registered the wallet | that credential holder, unrestricted | nothing outside the primitives, but the rules are empty — do not run value on this |
| **Policy, no approvers** | the operator of the agent | the credential holder, within the owner's limits, whitelists and caps | nothing outside the policy; the controller can freeze on chain at any time |
| **Policy with the owner as approver** | may be the platform or the agent | **no one without the owner's NEP-413 signature** | nothing; a proposal without the owner's signature never becomes a transaction |
| **Bound personal account** | the agent holds only a scoped extension | the account holder, always | nothing; the account's own keys stay with its holder, and the extension is revoked in one transaction |

These describe who may authorise a transaction. The next section is about
where the root itself lives, which is a separate choice.

> Availability: the first three configurations are live on mainnet.
> Personal account binding and per-customer vaults are on testnet and
> ship to mainnet with the next release.

## 7. Per-customer vaults: your own custody root

By default a wallet's keys descend from a shared root held by
DAO-approved enclaves. Convenient, and sufficient when the policy already
prevents unilateral movement. It has one property worth naming: the path
back to those keys runs through OutLayer's DAO.

A vault removes that. You deploy a small contract on an account you
create, and that contract becomes the issuer of your master secret:

| Property | What enforces it |
|---|---|
| The vault has no full-access key from the moment it is deployed | It is created in a single atomic transaction; its only key is a function-call key restricted to the MPC derivation call. That key cannot add keys, deploy code, or call anything else |
| The code is a version the DAO approved | The contract is referenced by hash as a published global contract. `outlayer vault verify <vault_id>` runs five independent on-chain checks, including that the hash is on the DAO's whitelist and that no unexpected access key exists |
| Your master is derived through the MPC network from **your** account | The derivation is a transaction on your vault, so its identity, and every issuance of it, are yours to audit |
| You can take it over unilaterally | Your parent account starts recovery; after an exit window you chose at deployment and that is readable on chain before anyone deposits, `finalize_recovery` deletes every OutLayer key and installs your key as the vault's only full-access key |
| You can take it over if we stop | If the DAO declares cessation, the same recovery opens on a fixed delay without any further action from us |

The trade-off is stated plainly on the vaults documentation: after the
exit window, the vault's parent can move the funds. That is the escape
hatch working as designed, and it is why the window is on chain for
counterparties to read before they deposit.

## 8. Leaving OutLayer

A sovereignty claim is only worth what the exit procedure is worth, so
ours is published as an operational runbook rather than a promise:
[`LEAVING_OUTLAYER.md`](LEAVING_OUTLAYER.md).

After running it you sign for the same wallet addresses with a key you
re-derive locally, and you decrypt the secrets bound to the vault
locally. Nothing changes address, and no value has to be moved to a new
wallet first. What you give up is everything that is OutLayer: minting
new wallets, issuing API keys, our execution layer.

It requires no cooperation from us — not our API, not our dashboard, not
our consent. The contract checks that the caller is the parent account
and that the time window has elapsed, and those are the only conditions.
We cannot cancel a recovery in progress. The runbook also lists what to
store offline beforehand, because a few identifiers (the vault id, the
wallet ids, the MPC verification key) are returned once and are needed to
re-derive specific keys later.

## 9. If you are a platform building on OutLayer

A platform that holds one credential covering every customer wallet is a
custodian of those wallets, whatever the infrastructure underneath is
capable of. The infrastructure does not make that determination; the
configuration does. Three patterns avoid it:

**Customer holds the credential.** Derive the wallet through us and hand
the credential to the customer at creation. The customer calls our API
directly, so your platform is never in the signing path and stores
nothing that can move funds. Best when the customer operates the agent
themselves.

**Platform proposes, customer signs.** The platform keeps a credential
for orchestration and the customer is the approver with a threshold of
one. The platform can assemble and submit work; it cannot complete a
transfer. Best when the platform drives the workflow but must not have
independent control.

**Customer's own account, scoped extension.** The customer's existing
NEAR account keeps its own keys and grants a revocable, policy-bounded
extension to the agent's executor. Best when the customer already holds a
wallet and wants to keep signing with it.

For escrow, hold the funds in an on-chain contract rather than in a
platform wallet. Funds locked by contract rules are not held by anyone,
and the release condition is public. If the release decision needs
judgement rather than a rule, the deciding code can itself run as an
attested OutLayer application: its build is measured, its key exists only
inside the enclave, and every decision carries a TEE attestation. The
decision is then made by code both parties can inspect, not by an
employee of the platform.

**On delegation.** An agent that transacts while its owner is asleep
needs delegated authority by definition. The useful question is not
whether delegation exists but how tightly it is bounded and who can
revoke it. A policy sets per-transaction and cumulative caps, restricts
recipients to a whitelist, limits which primitives are available at all,
and can require the owner's signature above a threshold while allowing
small routine actions to proceed. The owner can tighten or freeze it on
chain without asking anyone. That is a materially different arrangement
from one credential with unrestricted authority over every wallet, and it
is the arrangement we recommend designing toward.

## 10. What you can verify yourself

Nothing on this page asks for trust in a statement by OutLayer:

| Claim | How to check it |
|---|---|
| The wallet's policy is what you wrote | Read the entry in the contract; the ciphertext is public and only the enclave holds the decryption key |
| You are the controller | The controller account is stored with the entry and is what the contract checks on every update, freeze, and delete |
| The keystore is an approved build | Registrations, measurements, and the DAO's votes are on-chain records |
| Your master was issued only when you expect | Every issuance is a transaction; for a vault, it is a transaction on your own contract |
| A specific execution ran in a real enclave | Each call has an attestation containing the TDX quote, verifiable against Intel's certification service |
| The vault is intact and locked | `outlayer vault verify <vault_id>` runs five independent on-chain checks |


### Verifying the code itself

The chain records which build is approved. These steps tie that record
back to source you can read:

| Step | What it proves |
|---|---|
| Release published on GitHub with Sigstore certification | the binary was built by CI from the exact source at that tag; a substituted binary fails the signature |
| Rebuild from that tag | you can compare hashes yourself rather than trusting the published artifact |
| Five TDX measurements (MRTD, RTMR0-3) | firmware, kernel, application and runtime of the enclave that ran, not just the application layer — a debug image with a shell enabled fails even when the application matches |
| The on-chain approved list | the measurements of the enclave that signed for you are on a public, DAO-gated allowlist |
| Per-execution attestation | the TDX quote for that specific call, signed up to Intel's certification chain |
| `outlayer-verify` | an open-source binary that re-runs these checks on your own machine. Intel's root certificate is compiled into it, so a chain that does not end at Intel fails regardless of what we serve. It needs no account, no API key and no key material |

The full walkthrough, including both deployment methods and the
registration flow, is at https://app.outlayer.ai/docs/trust-verification.

## 11. Limits we state plainly

- **A wallet with no policy is unrestricted.** This is the single most
  important sentence on this page. Store a policy before funding a wallet.
- **Cross-chain swaps carry a residual trust in our coordinator.** For
  plain transfers, the enclave builds the transaction from the approved
  operation, so what is signed is exactly what was approved. For swaps and
  cross-chain withdrawals the route and deposit address are produced by a
  third-party solver at execution time and cannot be verified by the
  enclave offline. Approval binds whether the operation runs and pins the
  recipient; it does not bind the value terms of the swap. Capability
  gates, per-transaction caps and multisig apply, and both primitives are
  disabled by default.
- **Cumulative limits are best-effort under concurrency.** Daily, hourly
  and monthly caps are counted outside the enclave, so a burst of
  simultaneous requests can overshoot one. Per-transaction limits,
  multisig and freeze are enforced inside the enclave and are exact.
- **We can refuse service.** An operator can stop executing or shut down
  infrastructure. It cannot move funds, and with a vault it cannot prevent
  you from taking over your own keys.
