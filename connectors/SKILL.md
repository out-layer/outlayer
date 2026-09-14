---
name: outlayer-connectors
description: The OutLayer connector library — how an agent calls any connector (auth, the `operation` field, secrets, fees, quotas, refusal codes) and what each connector does. Use when an agent with an OutLayer custody wallet needs to reach a bank, a trading venue or another outside service, or when a connector call is refused and the reason has to be read.
---

# OutLayer connectors

A connector is a curated WASI module that runs inside the same TEE as your
wallet. It holds the credential for an outside service, it is priced per named
operation, and it can only reach the hosts its signed manifest declares. You
call it like any project; what makes it a connector is that the platform knows
its name and its prices.

## The call

```
POST https://api.outlayer.ai/call/connectors.outlayer.near/<connector>
X-Payment-Key: <a payment key the custody wallet owns>
X-Wallet-Id: <the wallet id>
X-Use-Owner-Secret: 1
Content-Type: application/json

{"input": {"operation": "<name>", ...}}
```

* **`operation` is mandatory and is the unit of price.** The contract, the
  coordinator and the worker all read that one field; a call without it is
  refused before anything runs and costs nothing.
* **`X-Payment-Key` must be a key the wallet itself owns** (create it from the
  wallet's own `wk_`), or the connector cannot see the secrets stored for you.
* **`X-Use-Owner-Secret: 1`** brings the secrets stored under your own wallet
  (policy, API tokens) into the run. To use a credential your owner stored under
  THEIR account and whitelisted you for, name it instead:
  `{"input": {...}, "secrets_ref": {"account_id": "owner.near", "profile": "gmail"}}`.
  Such a grant may carry an expiry, so a call that worked yesterday can be
  refused today with the date it lapsed on. With neither, the connector starts
  with no secrets and says so.
* Testnet: `https://testnet-api.outlayer.ai/call/connectors.outlayer.testnet/<connector>`.

The answer is always `{"success": bool, "output": {...}, "error": "...", "logs": []}`.

## Reading a refusal

| prefix | meaning | what to do |
|---|---|---|
| `policy_denied:` | the owner's policy refused (cap, coin, method, missing policy) | do not retry; change the request inside the caps, or ask the owner |
| `invalid_label:` / `sub_key_unavailable:` | a sub-key label was malformed, or this project has none | fix the label; only connectors have sub-keys |
| `wallet_busy` | another operation holds the wallet | poll `in_flight_request_id` if present, then retry once |
| `Daily connector quota reached` | the wallet's daily call budget is spent (refused calls count too) | wait; the budget grows with wallet age |
| `unknown_operation` / "does not sell operation" | the operation is not priced | read the connector's skill for the list |
| `invalid_secrets_ref` | the `secrets_ref` names no possible row: the account id is not one, or the profile is not 1–64 bytes or holds an ASCII character other than a letter, digit, `-` or `_` | fix the reference — `{"account_id": "<owner>", "profile": "<name>"}` |
| `Access denied by access condition` | the row exists but its condition does not admit your wallet | ask the owner to whitelist your wallet's 64-character account (`outlayer secrets access`), or name a row that does |
| `… its time limit passed at <date>` | you WERE granted and the grant has expired | ask the owner to grant again with a later date; being named again without one does not help |
| `… its AccountPattern \`…\` cannot be compiled as a regular expression` | the owner's condition holds a pattern the engine will not compile; the row refuses everyone, whatever its other branches say, until the owner fixes it | ask the owner to fix the pattern (`outlayer secrets access`) |
| the venue's own text | the outside service refused | act on it; the platform did its part |

## What a call costs

Compute (about $0.001 a call) plus the operation's fee on top. A run that
started is charged even when it answers an error — that is how a refusal by a
bank or a venue stays visible. Only a platform refusal before the guest runs
(no `operation`, quota, unpriced) costs nothing. A module that traps or times
out has its operation fee refunded.

## Secrets and keys

* **Your secrets** (policies, venue tokens) are stored by the wallet owner for
  one connector and reach only that connector's runs — either under your wallet
  (`outlayer secrets set-for-agent '{"KEY":"value"}' --project connectors.outlayer.near/<connector> --api-key wk_…`)
  or under the owner's own account with a whitelist naming your wallet, which
  you then name in `secrets_ref`. What you may read is decided by the row's
  on-chain access condition.
* **The connector author's own credential** is named in its manifest and is
  never yours to see or set.
* **Sub-keys.** A venue connector signs with a distinct key of your wallet per
  purpose: by convention `trading` (the venue account) and `bridge` (the EVM
  address funding legs pass through). They are your wallet's addresses under
  the owner's policy, and no other connector can reach them. The wallet's own
  EVM key is never signable from inside a connector.

## The library

| connector | what it is | skill |
|---|---|---|
| `hyperliquid` | Hyperliquid perpetuals: markets, leverage, limit and market orders, cancels, positions; funding over CCTP from the intents or the confidential balance | `connectors/hyperliquid-connector/SKILL.md` |
| `polymarket` | Polymarket prediction markets: find markets, buy and sell outcome shares, positions, claim resolved markets, fund from the wallet and back | `connectors/polymarket-connector/SKILL.md` |
| `gmail` | send mail from the owner's own Gmail address, under the owner's recipient policy; it cannot read the mailbox | `connectors/gmail-connector/SKILL.md` |
| `mercury` | Mercury business banking: pay a recipient (with the bank's approval rules), issue and cancel invoices, read the ledger | `connectors/mercury-connector/SKILL.md` |
| `connector-probe` | the platform's own test connector: pricing, limits, secrets, the outbound allowlist, traps and timeouts | `connectors/connector-probe/README.md` |
| `subkey-probe` | EVM sub-keys end to end, for testing the signing path | `connectors/subkey-probe/README.md` |

`polymarket` and the funding legs of `hyperliquid` run on mainnet only; the
probes are testnet only.

## Working with any connector

1. Call `status` first. Every connector has one, it is free or cheap, and it
   tells you whether a policy is stored and what it allows.
2. Size the request inside the caps `status` reports instead of discovering
   them by refusal — a refusal still costs the fee, because your call ran.
3. Long flows are step-shaped: an operation returns an `id` and you call
   `*_continue` until `step` is `done`. Never start a second flow while one is
   unfinished.
4. One call does one thing. Do not batch orders or payments into one call.
