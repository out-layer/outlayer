# Agent Custody: Outlayer (TEE) vs. TLA active-signer (on-chain MPC)

A side-by-side of the two custody models, followed by notes on each point.
The two are built for different jobs; this is meant to make the trade-offs
visible, not to declare a winner. The OutLayer column describes OutLayer's
code. The `active-signer` column describes that design as it was presented
to us; its figures are our estimates, not measurements.

## Comparison

| Dimension | Outlayer custody (TEE) | TLA `active-signer` (on-chain MPC) |
|---|---|---|
| Trust root | Intel TDX enclave, remotely attested (Intel DCAP / PCS), plus OutLayer's coordinator and, at this stage, OutLayer-held governance keys &nbsp;\* | NEAR MPC network + on-chain `active-signer` contract |
| Where the key lives | Derived on demand inside the keystore enclave from a master secret; never stored, no endpoint exports it. Stage caveat: the DAO account's full-access key can obtain the shared master outside an enclave | Held by no one — threshold-shared across MPC nodes |
| Producing a signature | One coordinator → keystore round trip, which includes one RPC view read of the on-chain policy; no transaction, no MPC round | Signer call + MPC yield/resume, multi-block (~2–6 s, estimate) |
| Overhead per signed action | None beyond the action's own transaction or intent | Signer function-call + MPC round + broadcast, on top of the action |
| Gas to produce a signature | None | ~0.003–0.008 NEAR/sig (estimate) |
| Chains from one custody | NEAR (ed25519), Solana (ed25519), EVM (secp256k1, one address on every EVM chain) | NEAR — `active-signer` builds NEAR transactions |
| Account onboarding | Implicit account — no `create_account` / `add_key` and no `intents.near` key registration | Named account — MPC-derive + `create_account` + `add_key` + funding for storage, **plus** `add_public_key` on `intents.near`, all on chain per agent |
| Concurrency | Money-moving operations on one wallet are serialized by the coordinator (velocity limits, NEAR nonces); separate wallets run in parallel | Per-account nonce commit serializes actions |
| Action set | Programmable policy: capabilities, limits, whitelists, approvals, reject-if-transaction guards | `function_call` + `transfer` only, enforced at the type level |
| Ownership transfer / resale | Not a native primitive | Native — compare-and-swap of the operating key |
| Built-in recovery | Of the custody root: per-customer vaults with a unilateral exit (testnet). Of an agent's authority: by composition | Native policy engine — timelock, watcher quorum, attestation |
| Human-readable identity | Implicit hex by default | Named (TLA sub-account, e.g. `agent.claude`) |
| Verifiability of authority | Remote attestation of the measured code; on-chain approval of measurements | On-chain contract logic + MPC network |

\* Both models root in MPC; the difference is *when* and *how often*.
OutLayer's wallet keys are derived (HMAC-SHA256) from a master secret that the
keystore obtains from the NEAR MPC network through an on-chain `request_key`
call on the DAO contract, which only an approved, attested keystore's access
key can make. The shared root is obtained when the keystore starts; a
per-customer vault's master is obtained through the customer's own vault
contract when the keystore first serves that vault. From then on the keystore
signs locally, with no MPC call per action. The `active-signer` model calls
MPC (`v1.signer`) on **every** signature. So it is not "TEE vs MPC": it is one
MPC derivation per master versus one MPC round-trip per signed action.

The master stays in enclave memory, with one exception at this stage:
`dao.outlayer.near` carries a full-access key, and a transaction signed with it
passes the `request_key` check, so its holder can obtain the shared master
outside any enclave. See
[Governance at this stage](https://github.com/out-layer/outlayer/blob/main/docs/NON_CUSTODIAL.md#governance-at-this-stage).

Ownership transfer, a built-in recovery engine for an agent's authority, and
human-readable names are first-class in the TLA model and not native to
OutLayer custody. Signing cost, signing latency, chain coverage and onboarding
are where the TEE model is stronger, and they come from one thing: signing is
local, not an on-chain round-trip. Concurrency is not a difference: both
serialize per account.

## Notes

### Latency and cost per action

OutLayer signs inside the keystore enclave, with no transaction and no gas to
produce the signature. The keystore reads the wallet's encrypted policy from
the chain (a view call, free) before it signs. The on-chain-signer + MPC path
pays, for **every** signed action, a function-call transaction into the signer
contract, an MPC signing round (yield / resume across several blocks), and a
broadcast. Both models pay the underlying transaction's own gas when the action
hits the chain; the difference is the signing overhead layered on top. At
wallet cadence — a few transactions a day — that overhead is negligible. At
agent cadence — many actions a minute — it dominates.

End to end, an OutLayer operation that moves money also waits for its own
settlement (a NEAR transaction, or an intent through the solver relay), which
is seconds, not milliseconds.

**Worked example — an agent doing one action per minute** (1,440 actions/day):

- *TLA `active-signer`:* ~0.003–0.008 NEAR of signing overhead per action →
  roughly **4–12 NEAR/day**, before the underlying transactions' own gas, plus
  the MPC round's latency on every action.
- *Outlayer:* **0 NEAR** of signing overhead. A free-tier wallet has a daily
  ceiling on custody operations; a subscription lifts it.

The `active-signer` figures are estimates — `1 TGas ≈ 0.0001 NEAR` at floor
gas price, tens of TGas burned along the `active-signer` → `v1.signer` →
callback chain (confidence: low–moderate). The point is the order of magnitude
and that the cost accrues **per action**.

### One custody, multiple chains

One wallet signs NEAR (ed25519), Solana (ed25519) and EVM (secp256k1); each
chain family has its own derivation seed, so a signature for one can never be
a signature for another. There is no per-chain signing contract to deploy. For
EVM and Solana the client builds and broadcasts the transaction; the keystore
only signs. The `active-signer` model, as designed, builds NEAR transactions.

### Onboarding: implicit accounts

Agents get NEAR implicit accounts — the account ID *is* the public key — so
there is no `create_account` and no `add_key`. A wallet can receive funds and
act on `intents.near` without any on-chain setup. The named-account model
requires on-chain account creation, funding for storage, and a key install per
agent.

There is a second, intents-specific cost. NEAR Intents authorizes a NEP-413
signature against a public key. For an implicit account the account ID *is*
that key, so Intents derives it directly and nothing needs to be registered.
For a named account the key cannot be inferred from the name, so it must be
registered with `intents.near` via `add_public_key` before Intents will
recognize the account — an extra on-chain call per agent.

### Programmable policy, evaluated next to the key

The keystore enclave that holds the key evaluates the wallet's policy before
every signature: capabilities per primitive (default-deny under a policy),
per-transaction caps, recipient whitelists, time windows, freeze and
multisig approvals. Two parts sit outside the enclave and are trusted to the
coordinator: the cumulative counters (daily, hourly, monthly caps and the
hourly rate limit), and, for five intents operations (swaps, cross-chain
withdrawals, confidential-intents operations, limit orders, payment checks),
the message that is signed. Details:
[Limits we state plainly](https://github.com/out-layer/outlayer/blob/main/docs/NON_CUSTODIAL.md#11-limits-we-state-plainly).

The `active-signer` model restricts the action set to `function_call` +
`transfer` at the type level, so dangerous actions cannot be expressed at all.
Ours is programmable; theirs is hard-restricted. Different tools for different
risk models.

### Compute and custody on one platform

OutLayer pairs custody with verifiable compute. An agent's logic runs in an
attested TDX worker and its keys are used in an attested TDX keystore; the
worker reaches the wallet through host functions that the coordinator routes
to the keystore. The agent can compute privately and sign the result without
leaving attested hardware, though the two run in separate enclaves with the
coordinator between them. The TLA model is a custody-and-ownership layer; it
has no compute component, and does not need one.

### Concurrency

The coordinator serializes money-moving operations per wallet: the velocity
limits need a consistent read-evaluate-record window, and NEAR transactions
from one account need ordered nonces. A second operation on a busy wallet
waits briefly, then is told `wallet_busy`. Separate wallets do not block each
other, so an agent that needs parallelism spreads it across wallets. The
`active-signer` model serializes per account on its nonce commit. Neither model
signs in parallel for one account.

### Trust assumptions

- OutLayer trusts the Intel TDX hardware and the DCAP / Intel PCS attestation
  chain, plus on-chain approval of the enclave's measurements. It is a
  single-vendor hardware trust root.
- OutLayer's coordinator is trusted for agent custody: it authenticates API
  keys, keeps the cumulative counters and pending approvals, and supplies the
  signed message for five intents operations.
- At this stage governance runs on single keys held by OutLayer: the DAO's
  full-access key, owner-only measurement approval, and contracts upgraded by
  key. See [Governance at this stage](https://github.com/out-layer/outlayer/blob/main/docs/NON_CUSTODIAL.md#governance-at-this-stage).
- The TLA model trusts the NEAR MPC network (threshold, no single holder) and
  the correctness of the `active-signer` contract.

These are different roots — threshold-distributed versus attested hardware
plus an operator — not one strictly stronger than the other. The cost,
chain-coverage and co-located-compute properties above are consequences of
the TEE root; the ownership, recovery and naming primitives are consequences
of the on-chain root.

### Where the two compose

Naming and recovery can sit **on top of** OutLayer custody without changing
the root: OutLayer's wallets are ordinary NEAR implicit accounts, so a policy
layer that targets ordinary NEAR accounts can target them. The sensible split
is one custody root (TEE, for agent-cadence signing) with a policy layer —
naming, ownership, recovery — composing above it.
