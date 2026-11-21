# Leaving OutLayer with your keys

A wallet's keys are held in a TEE. Whether its owner can take them out — and go on using the
same addresses with no OutLayer service — depends on how the wallet was made. There are
three kinds of wallet and two exits. Neither exit needs OutLayer's API, dashboard or
consent: each is a contract on NEAR, the NEAR MPC network, and a tool you run yourself.

| | Wallet with no owner | Owner exit | Vault exit |
|---|---|---|---|
| **How the wallet is made** | `POST /register` | a NEAR account registers in the keystore DAO; its wallets come from a link an agent hands over, or from the account's own signature | a vault contract is deployed on a sub-account; wallets are registered with its `vault_id` |
| **Set up by** | nobody | one transaction from any NEAR account | one transaction that creates the vault account |
| **Cost** | nothing | 0.05 NEAR, once per account; 0.01 NEAR per exit | 1 NEAR kept on the vault account |
| **Can the keys be taken out** | no | yes, by the owner account | yes, by the vault's parent account |
| **Wait before the keys leave** | — | 24–48 hours, chosen by the owner | 1–30 days, chosen at deployment |
| **What leaves** | — | the keys of every wallet of the owner | the keys of the vault's wallets and every secret bound to the vault |
| **Addresses afterwards** | — | the same addresses, signed for with keys you derive | the same addresses, signed for with keys you derive |
| **Coming back** | — | the same account gets new wallets, at new addresses | the vault is out for good; a new vault is a new one |
| **Works if OutLayer stops** | no | yes: the escrow of the keys is in the DAO contract, the key that opens it comes from NEAR MPC | yes; and a cessation declared by the DAO opens recovery on its own |
| **Can it be taken away** | — | by an upgrade of the DAO contract, which runs no earlier than the governance delay after its vote — time to leave first | no: a vault's code is fixed when it is deployed |
| **Who can hold it back** | — | the exit approvers, if the owner named any (a locked policy needs them) | nobody: the parent stands above every policy |
| **Secrets** | stay in OutLayer | stay in OutLayer | leave with the vault |
| **The runbook** | — | [OWNER_EXIT.md](OWNER_EXIT.md) | [LEAVING_OUTLAYER.md](LEAVING_OUTLAYER.md) |

## Which one

- **A wallet that holds value has an owner.** The owner exit costs one small transaction
  and nothing to run. An agent asks for it with `POST /wallet/v1/exit-link`, its user signs
  once, and from then on the user can leave with the keys whatever happens to the agent or
  to OutLayer.
- **A vault when secrets must leave too, or when no upgrade may ever touch the exit.** An
  application whose secrets — a `PROTECTED_` one, generated in the TEE and never shown,
  included — must be recoverable binds them to a vault. A vault's exit is not subject to
  OutLayer's governance at all.
- **A wallet with no owner is for a start.** It has no exit: its keys stay in OutLayer. It
  moves to a wallet with one at any time — a new wallet at a new address, the funds sent
  over by an ordinary transfer, venue accounts (Hyperliquid, Polymarket) opened again
  under it.

## What is the same for both exits

- The exit is a transaction on NEAR from the account that owns it, a wait that account
  chose in advance, and a claim. Nothing in it is a request to OutLayer.
- The wait is on chain for anyone to read, and lowering it takes effect only after the
  wait in force has passed: a stolen key cannot shorten the time its victim has to react.
- After the exit OutLayer no longer serves those wallets, and the wallet's policy no
  longer applies: the keys are the owner's, and so is every decision.
- Funds held by a venue under a key of its own — a Polymarket or Hyperliquid account — are
  withdrawn before leaving.

## What an exit is not

Leaving yields keys, not safety from a bad release that already ran. The governance delay
exists so that an upgrade is seen before it executes: an owner who does not like what was
voted leaves inside that time, and then moves the funds.
