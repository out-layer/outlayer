# Coordinator admin endpoints

Everything under `/admin/*` on the coordinator, what it does, and what it costs
if the credential leaks. Operational recipes with real tokens and hosts live in
`.idea/TESTING-WITH-ADMIN.md`; this file is the map and the security model.

## Authentication

One bearer token, `ADMIN_BEARER_TOKEN`, checked by `middleware::admin_auth` in
front of every route below. There is no second factor, no per-route scope and no
audit of who called what — the token IS the authorization.

```
Authorization: Bearer $ADMIN_BEARER_TOKEN
```

Three properties the code enforces:

* **The coordinator refuses to start** when the token is unset or shorter than
  24 characters. An unset variable falls back to a placeholder that ships in
  this repository — not a weak password but a published one — and nothing else
  about such a deploy looks wrong, so nothing else would say so.
  (`config::check_admin_token`)
* **The comparison is constant-time.** `==` on strings stops at the first
  differing byte, which turns one credential into a per-byte guessing game for
  anyone who can measure response times. (`middleware::admin_auth`)
* **A wrong token is `403`, a missing one `401`**, and neither says which.

What is NOT enforced, and matters when deciding who holds the token:

* No rate limit on `/admin/*`. The IP limiter sits on the HTTPS API routes.
* No per-route scoping. Anyone who can read `/admin/earnings` can also call
  `DELETE /admin/workers/{id}`.
* Nothing records which operator acted. `tracing` logs the action, not a person.

**Never put `/admin/*` behind the same hostname policy as the public API without
checking.** The routes are mounted on the same server; the only thing separating
them from the world is this header.

## What a leaked token can do

Ordered by what it costs, not by how it reads.

| Reach | Routes |
|---|---|
| **Turns the service off** | `PUT /admin/maintenance {"enabled": true}` — every route but `/health` and `/admin/*` answers 503 to everyone, workers included, until it is turned off; see below. |
| **Spends our money** | `POST /admin/grant-payment-key` `{owner, nonce, amount, note?}` — adds `amount` (minimal units, no cap) to an existing key's balance and marks it `is_grant`: that balance cannot be withdrawn or forwarded to a developer. Only a key with no user money on it (at most the $0.01 creation minimum, absorbed into the grant) or a key that is already a grant; a user-funded key is 409, a missing one 404. Refuses the trial key (nonce 0) with 400 and points to `grant-subscription`. `POST /admin/grant-subscription` `{owner, nonce, amount_usd?, days?, note?}` — sets what an existing key (the trial included) can spend from its allowance to exactly `amount_usd` (default `GIFT_SUBSCRIPTION_USD`) and runs it until at least now + `days` (default `GIFT_SUBSCRIPTION_DAYS`, 1–3650). `amount_usd` may be lower than `GIFT_SUBSCRIPTION_USD`, never higher (400). 409 when the key can already spend more than `amount_usd`; 404 when the key, or on nonce 0 the claimed trial, does not exist. On nonce 0 it converts the trial (`trial_converted`: no call count, `has_subscription: true`). It does not touch the key's balance or set `is_grant`; the allowance cannot be withdrawn or attached as `X-Attached-Deposit` (`allowance_no_deposit`). It also detaches the key from any sponsor code it carried (`sponsored_by`). Neither route can CREATE a key. `POST /admin/sponsor-codes` mints a code any wallet can redeem for up to `GIFT_SUBSCRIPTION_USD` of allowance on its nonce-0 key (created on redeem), `max_uses` times — see below. So a leaked token reaches: arbitrary non-withdrawable value on any existing unfunded or grant key through `grant-payment-key`, up to `GIFT_SUBSCRIPTION_USD` of allowance at a time through `grant-subscription` — the attacker's own keys included — and, through a code with no `max_uses`, that much on every wallet the attacker can mint until the code is switched off; all of it spendable on compute and connector operations at our cost. |
| **Breaks operations** | `DELETE /admin/workers/{worker_id}` — deletes every `worker_status` row of that id. `DELETE /admin/grant-keys/{owner}/{nonce}` — soft-deletes a grant key (`is_grant` only; 404 otherwise) and removes what is left of the grant from its balance (`payment_key_grant_revocations`); the owner's own money on the key stays, and they reach it by closing the key on chain and claiming the refund. A deleted key does not come back: a top-up on it is returned to the payer by the contract. A grant pays for calls and for nothing else: never withdrawn or refunded, no deposit to a developer, no subscription, no connector author share. |
| **Widens what the coordinator concludes** | `POST /admin/contract-wallet-code-hashes` — see below; a list whose growth relaxes a check. |
| **Reads customer data** | `GET /admin/earnings`, `/admin/connector-calls`, `/admin/egress-audit`, `/admin/compile-logs/{job_id}`, `/admin/health/detailed`. Egress audit is every outbound attempt every guest made. |
| **Reads customer data** (also) | `GET /admin/grant-keys?limit=&offset=` — every live `is_grant` key except unconverted trials: owner, nonce, balance, spent, reserved, project ids. `GET /admin/sponsor-codes` — which codes exist and how much their grants spent; no owners, no keys. |
| **Harmless to repeat** | `POST /admin/collateral/check`, `GET /admin/collateral/status`, `POST /admin/keystore-stats/refresh`, `POST /admin/connector-prices/refresh` — refreshes and reads, idempotent by construction. `collateral/check` reads the chain at most once per 30 s per process; a call inside that answers the stored coverage with `reread: false`. |
| **The monitoring token** (`MONITORING_BEARER_TOKEN`, not the admin token) | Opens `GET /admin/health/detailed`, `GET /admin/ops/events` and `POST /admin/collateral/check`, nothing else (any other admin route: 403). Reaches: per-instance health with node labels, and ops events — error and attack counts by route and code, with the client address (IPv4, or IPv6 /64) on attack signals, kept 30 days. `ops/events` takes `since` (at most 31 days back), `until`, `min_severity`, `kind`, `component` (`coordinator` or a worker type), `limit` (≤ 5000), newest first. |

## The allowlist

One list is a live table rather than an environment variable or a constant,
because it changes when a wallet build ships, and a coordinator restart — let
alone a keystore or worker release — is a worse thing to need than a row. The
enclave carries only what it *does* (verification logic); which builds the
counterparties run is data with an audit trail.

| List | Question it answers |
|---|---|
| `/admin/contract-wallet-code-hashes` | which contract-wallet builds may vote on an approval, and how their votes are resolved |

### `/admin/contract-wallet-code-hashes` — wallets that vote by contract

```
GET    /admin/contract-wallet-code-hashes
POST   /admin/contract-wallet-code-hashes   {"from_account": "...", "shape": "eip712|nep641", "note": "..."}
                                            {"code_hash": "...",    "shape": "eip712|nep641", "note": "..."}
DELETE /admin/contract-wallet-code-hashes/{code_hash}
```

A multisig approver without access keys — a NEP-616 wallet contract owned by an
EVM key or a passkey — votes with an `authorization` blob that its own contract
resolves (`w_resolve_auth`). Only an account running a build listed here may
vote that way. At ingest the coordinator reads the account's code hash (for a
global contract referenced by account id, the hash of the code published there)
and the row's `shape` says how to call the resolver: `eip712` for the EVM-owner
wallet, `nep641` for the passkey wallet. Every read for one vote is made at one
block and nothing is cached. An **empty table accepts no contract votes at
all**; key holders vote with NEP-413 signatures whatever this list holds.

`from_account` takes an approver wallet, not the account that publishes its
code: the coordinator follows the wallet's reference to the published code
itself. The migration seeds nothing — a build is a fact about one network —
so each network gets its rows here:

| Network | `code_hash` | `shape` | Wallet |
|---|---|---|---|
| mainnet | `FkAmDpjc2HaoFmU9xwgG6x5oJUXnpxAREtTMZi5UcgRy` | `eip712` | published by `eip712-wallet-contract.trezu.near` |
| mainnet | `qD9cxbe38rJn7BwUBtqaC2vVAiYD7TS4vnrafccHsRp` | `nep641` | passkey, published by `0saf343be226341c0eca7dba6d0b29d49bdff3ad03` |
| testnet | `BBL8qKk7uKDDairkMqtqGa3QBuZLiXS8zTowDeeL823y` | `nep641` | passkey, referenced by hash |

What a row is trusted for. The keystore does not read code hashes: at sign time
it checks that the approver is in the policy without a pinned key, calls
`w_is_signature_allowed` and `w_resolve_auth` on the approver's own account at
one block, and counts the vote only when the answer is the exact vote message.
So the keystore establishes that the approver's code cast the vote; that this
code is a supported wallet is established here. Forging a vote takes both a
row for code that approves anything AND control of the code on the approver's
account — a leaked token alone gives the first, not the second.

`DELETE` narrows: votes from that build are refused from then on. Votes already
stored stay; the keystore resolves them again before anything is signed.

## Sponsor codes — `/admin/sponsor-codes`

A sponsor code is a secret, `spn_…`, that gives the wallet redeeming it a
subscription on its nonce-0 key, paid by us: a link for a friend, a voucher
posted in public, or a partner's backend giving every agent it runs premium.
The wallet redeems it with `POST /wallet/v1/sponsorship {"code"}` under its own
credential (`wk_` or `near:`); the coordinator's `docs/SUBSCRIPTIONS.md` has
the redeem. For a person, hand out the `redeem_url` the mint answers with: it
opens the dashboard page that creates an agent wallet and redeems the code
with it.

| Route | Does |
|---|---|
| `POST /admin/sponsor-codes` `{name, allowance_usd?, grant_days?, max_uses?, redeem_until?, max_parallel?, one_per_ip?, lifts_custody_ceiling?}` | Mints a code. Answers `201 {id, code, redeem_url, …}`; **the code is shown once**, only its hash is kept. `redeem_url` is the link to hand a person (`https://app.outlayer.ai/redeem?code=…`): it carries the code and is as secret as the code. `allowance_usd` (minimal units) defaults to and is capped by `GIFT_SUBSCRIPTION_USD`; `grant_days` defaults to `GIFT_SUBSCRIPTION_DAYS`, 1–3650; `max_uses` absent is unlimited; `redeem_until` absent is until switched off; `max_parallel` (1–1000, default 1) is how many allowance calls one sponsored key may have in flight; `one_per_ip` lets each client address redeem the code once — default true when `max_uses` is set, false when it is not; `lifts_custody_ceiling` (default false) lets a grant of the code lift the free tier's custody ceiling (the `custody:*` per-day `unpaid` row of `operation_limits`; the migration seeds 100) as a bought subscription does. |
| `PATCH /admin/sponsor-codes/{id}` `{active?, max_uses?, max_parallel?, redeem_until?, lifts_custody_ceiling?, extend_days?, end_now?}` | `active: false` stops new redeems, what was granted runs to its end. `lifts_custody_ceiling` applies to the grants already given too: the tier is read on every custody call. `extend_days` tops every grant of the code back up to `allowance_usd` and moves its end to at least that many days from now (one gift per key; a key that can already spend more is skipped, counted in `skipped`; a key whose `wk_` was revoked is left out). `end_now` sets every live grant's `expires_at` to now. The two contradict each other and are refused together. |
| `GET /admin/sponsor-codes` | Every code with its settings, `uses` (times redeemed), `live` (keys carrying it whose grant has not ended) and `allowance_spent_usd` (spent by the keys carrying it). |

What to set, by use:

| Use | `max_uses` | `grant_days` | `one_per_ip` | `max_parallel` | `lifts_custody_ceiling` |
|---|---|---|---|---|---|
| a friend, premium for a year | 1 | 365 | — | 1 | as you decide |
| a voucher posted in public | 10 | 30 | true (default) | 1 | false (default) |
| a partner's backend (voulai) | absent | 90, then `extend_days` | false (default) | 99 | as agreed with the partner |

`one_per_ip` reads the address the rate limiter reads (`X-Real-IP`, else the
last `X-Forwarded-For` entry nginx appended), an IPv6 caller by its /64
(`ip_rate_limit::address_key`, shared by every per-address control); a request
with neither header is refused on such a code. A key carries one sponsor while its grant is live; after the
grant ends (its date, or `end_now`) the wallet may redeem another code. Every
redeem is kept (`sponsor_redeems`): a wallet never redeems the same code twice,
and an address never redeems a `one_per_ip` code twice, whatever the key
carried in between. A redeem refused for any reason — unknown code, switched
off, past `redeem_until`, used up, this wallet or this address already
redeemed it — answers `404 sponsor_code_invalid` and says no more.

## Maintenance — `/admin/maintenance`

One switch for an incident or a move: the API is off for everyone and comes
back as it was when the switch is turned off.

| Route | Does |
|---|---|
| `PUT /admin/maintenance` `{enabled, note?}` | On: every request but `GET /health`, `/admin/*` and a CORS preflight answers `503`, `Retry-After: 300`, `{"error":"maintenance","message":"…try again later."}` — clients and workers alike. Nothing is accepted and no work is handed out; a task a worker's poll had already taken off the queue goes back to it. Off: everything as before. Answers the stored switch. |
| `GET /admin/maintenance` | `{enabled, note, changed_at}`. |

The switch is stored in the database: a restart keeps it, and a copy restored
from a dump taken while it was on starts with it on. Background loops keep
running; when one of them is the problem, stop the container.

A worker caught mid-task cannot report its result while the switch is on.
Before a planned switch, soft-stop the workers first (`worker-ctl.sh stop` on
the node, `NAME=<cvm>` for a CVM other than the default; see
`deploy/self-hosted-tdx/docs/cvm-operations.md`): they finish what they
hold and take nothing new. The chain events they would have relayed are read
again from the saved block cursor when they start, if they were stopped for
fewer than 1000 blocks.

```bash
set -a; . scripts/.env; set +a      # ADMIN_BEARER_TOKEN_TESTNET
printf 'Authorization: Bearer %s\n' "$ADMIN_BEARER_TOKEN_TESTNET" | curl -sS -H @- \
  -X PUT https://testnet-api.outlayer.ai/admin/maintenance \
  -H 'Content-Type: application/json' -d '{"enabled": true, "note": "<why>"}'
```

## Adding an admin route

Two routers carry `admin_auth`, and new routes belong on one of them — the
wallet-state one exists only because those handlers need `WalletState`, and it
applies the same layer.

Before adding one, answer: does it spend, delete, relax a check, or expose
customer data? If yes, say so in the table above. A route whose reach is not
written down is a route nobody weighs when deciding who gets the token.
