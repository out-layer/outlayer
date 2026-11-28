# Agent On-chain custody: threat model

What each failure reaches, what it costs an attacker, how much money it puts
at risk, and what the owner does about it. The design itself is in
[ON_CHAIN_CUSTODY_DESIGN.md](ON_CHAIN_CUSTODY_DESIGN.md).

## The answers

**Funds at risk** means funds in the wallet contract, here and in section 2;
the hot wallet of [section 4](#4-a-cold-wallet-and-a-hot-wallet) is a
separate, optional balance.

| Threat | What the attacker needs | Funds at risk | What the owner does |
|---|---|---|---|
| The server that operates the service goes down | nothing | **none** | waits, or leaves through the owner exit with no OutLayer service |
| The server is compromised from outside | a remote exploit of the API host | **none**, for an agent that makes the SDK's checks | nothing |
| The TEE is read at the hardware level (DRAM interposer) | physical access to a powered-off keystore server, its root | **none** | nothing |
| NEAR MPC is compromised | 11 of the 16 mainnet nodes | **none** | nothing |
| OutLayer's governance is used against its users | a quorum of the OutLayer DAO's members | **none** | leaves through the owner exit (24 to 48 hours) before a change of the DAO contract's code or of the approved builds takes effect (72 hours after its vote) |
| The agent's machine or model is compromised | the agent's host, or a prompt injection | **what the policy allows** without the owner | freezes; then sets up a new agent key and wallet contract, allows that account in the policy, unfreezes and moves the funds, or leaves through the exit; replaces the agent's API and payment keys |
| The owner's key is stolen, policy locked | the owner's key | **what the policy allows** per period, on a wallet contract account with no access key | with the approvers, moves the funds out; replaces the key |
| A relayer, proxy or RPC on the path | a position on the network | **none** | nothing |

**What the policy allows** is the owner's choice: the kinds of operation,
the tokens, limits per transaction and per period (hour, day and month),
receivers on an allowlist, and approvals by M of N above a threshold. The
enclave judges the per-transaction limit, the kinds, the tokens, the
allowlist, the approvals and the freeze from chain data; the amounts per
period are counted by the OutLayer API and passed to the enclave.

On a wallet contract account with no access key (the `0s…` default and a
sub-account the setup made), nothing leaves the wallet contract without both
signatures, and the enclave gives its own only to an operation the owner's
policy allows. None of the systems in the table moves funds alone.

## 1. The path the money takes

The agent's balance sits in its NEAR Intents wallet contract. The chain
executes a move only with two signatures:

* **A, the agent's key.** Made from one signature of the owner's own key
  (NEP-413), and kept by the agent. No OutLayer service holds it; the owner
  makes it again by signing again with the same key of their account that
  signed at setup.
* **E, the enclave's key.** Derived inside the OutLayer keystore enclave
  (Intel TDX) from the owner's master, at the moment of signing. NEAR MPC
  gives the master secret only to an enclave whose build and instance the
  OutLayer DAO (`dao.outlayer.near`) approved.

For each operation the agent signs a request; the enclave reads the owner's
policy and the wallet contract from the chain, checks the operation, builds
the wallet contract's request and adds E; the agent compares that request
with what it asked for and signs last with A. Any NEAR account relays it.

The owner's master is also escrowed in the DAO contract under a key only NEAR
MPC produces for that owner's account: the owner exit.

## 2. Each threat

### 2.1 The service goes down

OutLayer's API, keystore or servers stop, for an hour or for good.

* **Funds at risk:** none. The balance stays in the wallet contract; nothing
  signs.
* **What stops:** the agent's operations, until the service is back.
* **The owner** leaves alone through the owner exit: they start it from their
  own account on the DAO contract, wait the window they chose (24 to 48
  hours), and claim the master within 7 days. From it they derive E, their
  wallet repeats one signature, with the same key of the owner's account that
  signed at setup, and gives A, and an offline tool builds a request with
  both halves that any NEAR account relays. NEAR and NEAR MPC are
  enough; no OutLayer service takes part.

### 2.2 A server is compromised from outside

An attacker holds the API host: the coordinator, its database, its queue.

* **Funds at risk:** none, for an agent that makes the SDK's checks. The
  server holds neither key and can produce neither signature.
* **Operations.** The enclave signs only an operation the agent signed, held
  to the policy the enclave reads from the chain itself. With this server
  compromised, what holds is the per-transaction limit, the kinds, the
  tokens, the allowlist, the approvals and the freeze; the amounts per period
  are counted by this server. The agent's SDK checks what comes back before
  the agent signs: the receiver, method, arguments and amount of the request; for a swap or a withdrawal to another chain, the
  1Click deposit address, which the SDK looks up at 1Click itself (the
  recipient, the refund address, the assets and the amounts of that quote).
* **Setup.** The page seals the owner's signature to a key that is in the
  link the agent gave its owner, so it reaches the agent and no one else.
  The agent verifies that signature, reads on chain that it was made by a
  full-access key of its owner, derives A from it itself, and takes the
  account only when the chain shows it holds A and E. The page and the agent
  take E only with a statement signed by a keystore key the OutLayer DAO
  approved, checked on chain.
* **Cost:** a remote exploit of an internet-facing service, the cheapest
  attack on any provider. That is why the funds do not depend on that server.

### 2.3 The TEE is read at the hardware level

A DRAM bus interposer reads an enclave's memory
([TEE.fail](https://tee.fail), 2025: DDR5, Intel TDX and AMD SEV-SNP).

**This is a property of the hardware, not of a design.** It applies to every
system under consideration that relies on a TEE: a policy co-signer in a TEE,
the NEAR MPC network (its 16 mainnet nodes run in TEEs), and the OutLayer
keystore alike. What a design controls is what one TEE break reaches.

* **What it needs:** physical access to the specific server in its data
  centre and root on its host.
* **It cannot be done to a running enclave.** The interposer goes between a
  memory module and its slot, with the server powered off, and powering off
  erases the master: it lives only in the enclave's memory.
* **What it yields by itself:** nothing. The keystore that starts after the
  power cycle is a new instance with no master. NEAR MPC gives it the master
  only after a DAO vote that names its key, so the attack works only if the
  DAO approves an instance on a server that went down for no known reason.
  In that case the attacker reads the master, and so E.
* **Funds at risk:** none. A is not in the enclave, and the agent signs last:
  the enclave's half exists only for an operation that passed the policy, and
  no half-signed move waits anywhere to be completed.
* **A forged attestation** made with keys extracted this way from the
  attacker's own machine does not get the master: a keystore instance needs a
  DAO vote that names its key.

### 2.4 NEAR MPC is compromised

An attacker controls the threshold of the NEAR MPC network: 11 of its 16
mainnet nodes (read from `v1.signer`, 2026-11-28).

* **What it yields:** the master MPC derives for the DAO contract, so E.
* **Funds at risk:** none. A comes from the owner's own signature, not from
  MPC.
* **Cost:** eleven independent operators, each in a TEE: their collusion, or
  the attack of 2.3 eleven times.
* **NEAR MPC unavailable:** running keystores keep working; a new keystore
  instance, an owner's first wallet (its escrow is written with MPC) and the
  owner exit wait for MPC.

### 2.5 OutLayer's governance is used against its users

A build that leaks the master is approved through the OutLayer DAO.

* **What it needs:** the keys of a quorum of the DAO's members; the DAO
  contract changes only by their vote.
* **What it yields:** E at most.
* **Funds at risk:** none. E moves nothing without A.
* **The owner can leave before a change is in force.** A change of the DAO
  contract's code or of the approved builds takes effect 72 hours after its
  vote, in the open, on chain. The owner exit takes 24 to 48 hours, so an
  owner who does not accept a change leaves with both keys before it is in
  force.

### 2.6 The agent's machine or model is compromised

Malware on the agent's host, a stolen key A, or a prompt injection.

* **Funds at risk:** what the policy allows without the owner. Every operation passes the enclave's
  policy: the kinds of operation the owner allowed, the limits per
  transaction and per period, the allowlist of receivers, approvals above the
  threshold. An injected request is judged like any other.
* **Cost:** the cheapest of all; a prompt injection is free. This is what the
  policy is for.
* **The owner** freezes the wallet with one transaction from their own wallet,
  straight to the contract. A freeze stops new requests at once; a request
  prepared in the last ten minutes can still execute. The owner then sets up
  a new agent key and wallet contract, allows that account in the policy,
  unfreezes and moves the funds, or leaves through the owner exit. The
  agent's API key and payment key were on the same host, so the owner
  replaces them too.

### 2.7 The owner's key is stolen

* **With a locked policy**, on a wallet contract account that has no access
  key: what the policy allows per period. A change of the policy, its unlock
  and the owner exit each need the approvers' quorum, which the stolen key
  alone is not. The approvers and the owner then move the funds out, and the
  owner replaces the key. A wallet contract installed on the owner's own
  account is under that account's keys.
* **The owner exit** takes the window the owner set, and any single approver
  cancels it.
* The lock is the owner's choice; the approvers can be a Ledger, a second
  person or a DAO.

### 2.8 The relayer or the network

The signed request covers the chain, the wallet contract, the nonce, its
creation time and the single promise with all its fields. A relayer, a proxy
or an RPC on the way can hold it back for at most its 10-minute timeout; it
cannot change it.

## 3. UX and DevX

| | |
|---|---|
| What one operation depends on | one NEAR transaction with two Ed25519 checks. No signing round of NEAR MPC: operations go on while MPC is unavailable |
| Who signs an operation | the agent, by itself, inside the policy. The owner signs nothing per operation; they are asked only above the limits they set |
| Code under the funds | one signing standard with no state and no clock, on the NEAR Intents wallet contract |
| Beyond the chain | connectors to web2 services and venues, and the secrets they use; the connector's own rules and the owner's approvals apply |
| Setup by the owner | one signature and one transaction in their own wallet for the wallet contract (about 0.01 NEAR of gas); before it the owner registers once for the exit (0.05 NEAR) and stores a policy; the agent's working account keeps 0.5 NEAR for relays; by default the wallet contract has no access key and holds no NEAR for storage |
| The agent's key | made by the owner's signature, again whenever needed with the same key of the owner's account that signed at setup; nothing to back up |
| One operation | two HTTPS calls, each signed by the agent's key, and the agent's signature on the move; one NEAR transaction, relayed by any account |
| Chains | NEAR and NEAR Intents; other chains through 1Click swaps and withdrawals |
| The owner's controls | policy, approvals in their own wallet, freeze, lock, exit |
| Integration | the OutLayer JS SDK and agent skills; nothing to deploy, no contract of one's own |

## 4. A cold wallet and a hot wallet

The agent works the way an exchange runs its wallets:

* **The cold wallet** is the wallet contract: everything above. The main
  balance stays there, under two signatures.
* **The hot wallet** is the agent's TEE custody account, OutLayer's
  enclave-held account, signed by the enclave alone under the same policy:
  one API call per move and no NEAR transaction per move, on EVM chains,
  Solana, trading venues, a confidential balance, and connectors to web2
  services.

For work that needs the hot wallet, the agent moves the amount the operation
needs out of the cold wallet, as one operation under both signatures and the
policy, does the work, and sends everything back to the cold wallet when it
is done: its OutLayer skills instruct it to. One policy covers both, with the
same limits and approvers, and the owner sets how much may leave the cold
wallet.

## 5. What is already running

Nothing in this model waits to be built:

* **The OutLayer keystore** on OutLayer's own TDX servers, its builds and
  instances approved by the OutLayer DAO, its master from NEAR MPC.
* **The DAO contract** `dao.outlayer.near`: approved builds, the master by
  MPC CKD, and the owner exit, live on mainnet.
* **The policy engine**: limits, allowlists, M-of-N approvals, freeze and the
  policy lock, on mainnet.
* **Agent On-chain custody**: the two-key signing standard on the NEAR
  Intents wallet contract, the enclave's side, the API, the JS SDK and the
  owner's setup page, running end to end on testnet.

On chain, the code under the funds is the NEAR Intents wallet contract and
one signing standard of about two hundred lines with no state and no clock.
No OutLayer contract sits on the path of the money, and none that OutLayer
can upgrade.
