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
| **Spends our money** | `POST /admin/grant-payment-key` — funds an existing key from our balance and marks it `is_grant`: that balance cannot be withdrawn or forwarded to a developer. Refuses the trial key (nonce 0) with 400 and points to `grant-subscription`. `POST /admin/grant-subscription` `{owner, nonce, amount_usd?, days?, note?}` — sets what an existing key (the trial included) can spend from its allowance to exactly `amount_usd` (default `GIFT_SUBSCRIPTION_USD`) and runs it until at least now + `days` (default `GIFT_SUBSCRIPTION_DAYS`, 1–3650). `amount_usd` may be lower than `GIFT_SUBSCRIPTION_USD`, never higher (400). 409 when the key can already spend more than `amount_usd`; 404 when the key, or on nonce 0 the claimed trial, does not exist. On nonce 0 it converts the trial (`trial_converted`: no call count, `has_subscription: true`). It does not touch the key's balance or set `is_grant`; the allowance cannot be withdrawn or attached as `X-Attached-Deposit` (`allowance_no_deposit`). Neither route can CREATE a key. So a leaked token reaches: arbitrary non-withdrawable value on any existing key through `grant-payment-key`, and up to `GIFT_SUBSCRIPTION_USD` of allowance at a time through `grant-subscription` — the attacker's own keys included — spendable on compute and connector operations at our cost. |
| **Breaks operations** | `DELETE /admin/workers/{worker_id}`, `DELETE /admin/grant-keys/{owner}/{nonce}` — remove records other things rely on. |
| **Widens what the coordinator concludes** | `POST /admin/binding-zones`, `POST /admin/hos-impl-code-hashes`, `POST /admin/hos-impl-versions`, `POST /admin/wallet-code-hashes` — see below; all are lists whose growth relaxes a check. |
| **Reads customer data** | `GET /admin/earnings`, `/admin/connector-calls`, `/admin/egress-audit`, `/admin/compile-logs/{job_id}`, `/admin/health/detailed`. Egress audit is every outbound attempt every guest made. |
| **Harmless to repeat** | `POST /admin/collateral/check`, `GET /admin/collateral/status`, `GET /admin/binding-implementations`, `POST /admin/keystore-stats/refresh`, `POST /admin/connector-prices/refresh` — refreshes and reads, idempotent by construction. |

## The allowlists

All of them are live tables rather than environment variables or constants,
because all of them change when a partner ships something, and a coordinator
restart — let alone a keystore or worker release — is a worse thing to need than
a row. The rule that put them here: the enclave carries only what it *does*
(decoders, verification logic); who the counterparties *are* (which code, which
version, which zone) is data with an audit trail. They move in **opposite
safety directions**, which is the only thing worth memorising about them.

Four lists, one question each:

| List | Mode | Question it answers |
|---|---|---|
| `/admin/binding-zones` | both | which account names the lifecycle webhook may speak about |
| `/admin/hos-impl-code-hashes` | `hos_lease` | which implementation code we recognize on a leased account |
| `/admin/hos-impl-versions` | `hos_lease` | which nested-request decoder reads each partner `impl_version` |
| `/admin/wallet-code-hashes` | `personal_account` | which wallet builds we recognize on an owner's own account |

`GET /admin/binding-implementations` reads what every live binding runs right
now and holds it against the lists — the operator's early warning.

### `/admin/binding-zones` — where a revoke webhook may point

Account-name suffixes the partner's binding webhook is allowed to name. The
effective list is the union of this table and the deploy-time
`BINDING_WEBHOOK_SUFFIXES`.

**Empty means no restriction.** Adding the first zone NARROWS what the endpoint
accepts — the safe direction to move in by accident.

```
GET    /admin/binding-zones
POST   /admin/binding-zones          {"suffix": "...", "note": "..."}
DELETE /admin/binding-zones/{suffix}
```

A suffix set in the environment cannot be removed here; if it is still listed
after a DELETE, it came from the deploy.

### `/admin/hos-impl-code-hashes` — implementations we recognize

Answers exactly one question, for `hos_lease` bindings: when the leased
account's `hos_agent_status` will not answer, is that the chain telling us
something about the account, or a condition we must not act on?

It authorizes nothing. The spend grant on the leased account does that, and the
contract enforces it whatever this table says.

**Empty means we conclude nothing** — the same behaviour as before the list
existed. Adding a hash is what makes a refusal from an account running something
else readable as evidence, so a row WIDENS what the coordinator is willing to
conclude. That is the less-safe direction, and it is why this is an admin action
rather than a config default.

An unrecognized implementation produces `CodeHashUnknown`, which **suspends**
the binding and never revokes it: the fault is reversible, so recognizing the
code later brings every affected lane back with nothing rebuilt. That is
deliberate. The refusal that triggers it also covers a contract that panicked
once, a partner mid-migration, and a response this build cannot parse — a
terminal fault there would stamp `revoked_at` on every live leased binding with
no way back.

```
GET    /admin/hos-impl-code-hashes
POST   /admin/hos-impl-code-hashes   {"from_account": "...", "note": "..."}
                                     {"code_hash": "...",    "note": "..."}
DELETE /admin/hos-impl-code-hashes/{code_hash}
```

**Do not read the hash off the leased account.** These accounts reference a
global contract BY ACCOUNT ID, which leaves their own `code_hash` at the
all-zeros sentinel — the code that identifies them is on the implementation
account, one view further on. Send `from_account` and the coordinator makes that
hop itself (`near_client::fetch_impl_code_hash`); the sentinel is rejected
explicitly, because listing it would make every codeless account "recognized".

And because the indirection is **mutable** — whoever owns the implementation
account can redeploy it with no event on the leased accounts at all — a hash
here is a fact about a moment, never a guarantee about a period. An upgrade on
their side stops matching, the affected bindings go `suspended`, and adding the
new hash restores them.

`DELETE` narrows: with nothing recognized the coordinator stops calling anything
foreign. Safe to do in a hurry.

#### What adding a hash turns on

Both paths at once, and there is no second switch. The list is the only control:

* when the status view **refuses**, an unrecognized implementation is what makes
  that refusal readable as evidence rather than as a condition to sit out;
* when it **answers**, the answer counts only if the code that answered is on
  the list — otherwise the leased account, which serves `hos_agent_status`
  itself, is believed on its own say-so about the grant, the membership and the
  lease.

So the first `POST` is not a preparation, it is the change. Everything running
an implementation you did not list goes `suspended` — reversibly, and a `DELETE`
puts it back.

It cannot fail closed by accident. A mismatch has to be POSITIVE: an empty list,
an unreadable list, an account that states no code and an unreachable node all
mean "no basis to call anything foreign" and pass straight through. An RPC blip
cannot suspend anything, and neither can a table nobody filled in — which is why
"nobody configured this" and "this is switched off" are the same state and
cannot drift apart.

Cost, and where it lands. The database is asked first and an empty table returns
before any RPC, so an unused list costs one local query per observation. With a
list, the extra work depends on the account: one that deploys its code inline
states its hash in the view already fetched and costs nothing more; one that
names a global contract by account id — which is what these leased accounts do —
costs one further `view_account`. On the refusing path that lands exactly when
the chain is already slow, which is the trade the table buys. The five-second
observation cache absorbs bursts on the signing path; nothing caches it on the
status path.

**On testnet, the list and the `hos_lease` stub suite collide.**
`tests/hos_lease_stub_e2e.sh` binds to a stub contract we deploy, and that stub
is by definition not a partner implementation — so the first hash added suspends
its bindings and the suite goes red. List the stub's implementation beside the
partner's: run the suite with `KEEP=1` and
`POST {"from_account": "<the stub account it printed>"}` while it is up.

### `/admin/hos-impl-versions` — which decoder reads each partner version

A decoder is CODE: the frozen wire structs of one `w_execute_extension` request
schema, compiled into the shared crate and therefore into the keystore's
measured image (`hos::DECODERS`, today `[1]`). Which partner `impl_version` a
decoder reads is DATA, and it lives here — the partner renumbers on every
redeploy of their implementation whether or not the wire changed, and a mapping
compiled into the enclave made each of their releases a release of ours.

```
GET    /admin/hos-impl-versions
POST   /admin/hos-impl-versions      {"impl_version": 7, "decoder_version": 1, "note": "..."}
DELETE /admin/hos-impl-versions/{impl_version}
```

The listing carries `decoders`: the decoder numbers the running build carries. A
`POST` naming any other decoder is refused — a row like that would let PUTs
through and have every signature refused at the enclave, the same lock one step
later and harder to read.

**A row is added on the partner's word, never on the chain's.** The chain
reporting a new number says nothing about the schema behind it; a schema read by
the previous decoder parses and means something else, which is exactly the
failure the version gate exists to refuse. Ask, then add.

What a missing row does: every binding whose account reports that version goes
`suspended` (`unsupported_wallet_implementation`, reversible), and a `PUT`
stating it is refused with the supported set named. Adding the row brings the
lanes back with nothing rebuilt. `DELETE` narrows — safe in a hurry.

### `/admin/wallet-code-hashes` — wallet builds we recognize

The `personal_account` analogue of the leased hash list: the wasm code hashes
of the upstream wallet contract an owner installs on their own account. A build
the owner installs that is not listed fails verification with the reversible
`unrecognized_wallet_code`; adding the row — or the owner restoring a listed
build — brings the binding back.

```
GET    /admin/wallet-code-hashes
POST   /admin/wallet-code-hashes     {"from_account": "...", "note": "..."}
                                     {"code_hash": "...",    "note": "..."}
DELETE /admin/wallet-code-hashes/{code_hash}
```

Same request shape as the leased list (`from_account` follows a global-contract
reference, the no-code sentinel is refused). One difference in the empty case:
**an empty table recognizes nothing.** The personal mode has no other evidence of
what an account runs, so it cannot fall back to "conclude nothing" the way the
leased list does; the migration seeds the build the profile was written against.

The worker reads this list too (`GET /internal/wallet-code-hashes`,
worker-token authenticated): it verifies a bound account on chain with the same
crate verdict before running as it, and that verdict needs the deployment's
answer to "is this build recognized?".

### `GET /admin/binding-implementations` — what the live bindings run

On demand, like the collateral check: one or two view calls per live binding,
nothing cached, nothing changed. For each binding: the code hash the account
actually runs (through the global-contract reference where there is one) and
whether the relevant list has it; for leased accounts also the `impl_version`
the account reports now, the one recorded at PUT, and whether a row maps it.

Three counts at the top — `unrecognized_code`, `unmapped_versions`,
`unreadable` — are the numbers to alarm on. The first two mean a partner
shipped: every lane behind them is, or is about to be, suspended by a fact one
`POST` above fixes. Each affected binding also says so itself —
`GET /wallet/v1/binding` carries `status_reason` (`unrecognized_wallet_code`,
`unsupported_wallet_implementation`, ...) whenever it is not `active` — but that
is one binding at a time, read by whoever polls it. This is the fleet in one
answer; poll it from the status page.

## Adding an admin route

Two routers carry `admin_auth`, and new routes belong on one of them — the
wallet-state one exists only because those handlers need `WalletState`, and it
applies the same layer.

Before adding one, answer: does it spend, delete, relax a check, or expose
customer data? If yes, say so in the table above. A route whose reach is not
written down is a route nobody weighs when deciding who gets the token.
