# Building a connector

A guide for developers writing connectors on OutLayer. It covers what a
connector is, what being one changes, how secrets reach your code, and every way
a call to you can be limited.

The manifest format itself has its own document —
[`wasi-examples/CONNECTOR_MANIFEST.md`](../wasi-examples/CONNECTOR_MANIFEST.md).
Read this first for the model, that one for the field-by-field reference.

---

## 1. What a connector is

**A connector is an ordinary project that we curated and priced.** There is no
separate connector runtime, no special deployment, no second API. You write a
WASI module, publish it like any project, and what makes it a connector is
decided from two facts:

* it is published under the curated namespace (`connectors.outlayer.near` on
  mainnet, `connectors.outlayer.testnet` on testnet), and
* its wasm carries a manifest declaring a `connector_id`.

Membership is a comparison against the owner account of a `project_id`, which
makes "is this a connector" a structural fact rather than something a project
claims about itself.

### Why the category exists at all

An ordinary project runs your code for you. A connector runs your code **for
somebody else's agent**, inside a TEE that holds custody keys, and lets it reach
the internet. Three things follow, and they are the whole difference:

| | ordinary project | connector |
|---|---|---|
| outbound network | open | **only the hosts your manifest declares** |
| operation naming | your business | a required top-level `operation` string |
| pricing | per call | **per operation, on chain** |

Each is a constraint on you. Together they are what lets a stranger's agent call
your code with money attached and a wallet in the room.

### What a connector is NOT

It is not a plugin, an extension, or anything that runs inside another program.
Your module is a normal WASI guest with a normal entry point. It cannot see
other calls, other agents' secrets, or the wallet's keys — the same isolation
every project gets.

It is also not a way to charge whatever you like. Prices live on chain and
nowhere else, and the contract refuses a call that does not attach the exact
price of the operation it names. A price baked into your wasm could only ever
disagree with the one that decides.

---

## 2. The shape of a call

Every connector call names its operation in one place:

```json
{ "operation": "send", "to": "someone@example.com", "subject": "hello" }
```

Over HTTPS that object is the `input` of `POST /call/{owner}/{project}`; on
chain it is `input_data` in `request_execution`. Same bytes either way, and four
readers take the operation out of them: the contract prices the call, the
coordinator bills it and picks which limit applies, the worker refuses a
connector call that names none, and your guest dispatches on it.

**Fail-closed, before your code runs.** Absent, blank, not a string, nested, or
spelled `op` — all refused. None of them defaults, because a defaulted operation
is a defaulted price and the cheapest one is what an attacker would pick.

An operation with no on-chain price is refused too. Unpriced is not free.

**A connector runs its active version, and only that.** The `version_key` a
call may otherwise use to pin a published version is refused on a connector
project (`invalid_version_key`, 400). An older version would run an older
manifest — its network allowlist and its declared limits — and older code
under the curated name, and its manifest report would replace the connector's
declared limits for every caller until the active version ran again. To take a
version out of service, switch the active version and `remove_version` it on
chain; publishing a fix alone leaves the old one callable on ordinary projects,
and never callable on a connector.

Two constraints come with the format: a priced project's request must be a JSON
object, and on chain it must be at most **10 KB** — the contract parses it, and
the caller's gas pays for that. A connector that moves more than that takes a
reference, not the bytes.

### Answering

Return JSON on stdout. The convention the playground and the connectors follow:

```json
{ "success": true, "output": { … }, "logs": [], "error": null }
```

The field is `error`, not `error_message`.

### Answering on chain: seal what must not be public

An answer over HTTPS is seen by its caller. An answer on chain is written into
the transaction's result and is readable by anyone, for ever. So anything a
connector would say freely over HTTPS but must not publish — an owner's policy,
which names people, accounts or markets — is **withheld on chain unless the
caller gave it a key to seal to**.

The convention, so every connector's owner page can read every connector's
policy the same way:

* `status` takes an optional `reply_pubkey`: a secp256k1 public key in hex —
  33 bytes compressed, the form `eciesjs` gives. Given one, the sensitive part
  of the answer comes back sealed to it — `policy_sealed`, base64 — and the open
  part says only `{"present": …, "sealed": true}`.
* Without one, `OUTLAYER_EXECUTION_TYPE` decides: `HTTPS` answers in the clear;
  anything else withholds the fields and says how to ask
  (`{"present": …, "sealed": false, "note": …}`). Fail-closed: a missing
  variable is treated as public.
* The seal is the pair near.email runs on: the `ecies` crate in the guest
  (`default-features = false, features = ["pure"]`), `eciesjs` in the browser —
  secp256k1 ECDH → HKDF-SHA256 → AES-256-GCM, in a format the two libraries
  keep compatible with each other, so nothing about the bytes is ours to get
  wrong. The keystore's own ECIES (X25519) is the other direction, browser →
  enclave, and the two never meet. Randomness comes from `getrandom`, which the
  executor provides to a wasip2 guest.

`openReply` in the dashboard's `lib/ecies.ts` opens it, and `test/ecies.test.mjs`
shares a golden vector with the connector's sealer so the two cannot drift
apart unnoticed. `connectors/gmail-connector/src/seal.rs` is the reference —
copy it.

Why a key from the caller and not a decrypt path in the keystore: the keystore
never returns a plaintext to anyone, and a "read only these keys" door would be
the first exception. Running the connector is already a door the owner may use,
and it costs a transaction, which is the honest price of reading something the
enclave holds.

---

## 3. Network: you declare it, the worker enforces it

A connector reaches only the hosts listed in `capabilities.network` in its
manifest. Exact hostnames, case-insensitive, **no implicit subdomain wildcard**:
`example.com` does not permit `evil.example.com`.

The manifest lives in a wasm custom section, so it is covered by the SHA256 the
contract records for the version. Nobody — not you after publishing, not the
coordinator operator — can widen it without publishing a new version that users
have to move to.

A connector with no manifest section reaches **nothing**. That is the
fail-closed direction, and `build.sh` in `connector-probe` fails the build when
the section is missing so you find out at your desk.

Every outbound attempt is reported to the coordinator with whether the allowlist
permitted it. The coordinator stores that trail and decides nothing — the
allowlist is enforced inside the worker, where the keys are.

**Each request has 30 seconds, and two that run out end the run.** A request
that exceeds the timeout fails; the second one aborts the execution outright,
because a guest still retrying a host that does not answer is spending paid
time on nothing. Poll a slow venue with short requests and your own backoff,
not with one long call. The execution limit itself is the coordinator's per
call; a bridge that needs minutes takes a step per call and keeps its
checkpoint in project storage.

There are no raw sockets: the guest's only network path is `wasi:http`. TCP,
UDP and name lookups are refused by the worker, so nothing can go around the
allowlist or the audit trail.

**A host may be unreachable from some nodes, and that is handled by placement,
not by your code.** Executors sit in more than one country, and a venue can
refuse one of them: Polymarket's CLOB answers order placement with
`403 Trading restricted in your region` to a US address while serving reads,
cancels and its relayer from everywhere. The operator of such a node lists the
routes it cannot run (`EXECUTE_EXCLUDES`, `<project>:<operation>`), and the
coordinator gives those calls to a node that can. Your connector therefore sees
one behaviour everywhere and needs no fallback of its own. What you should
still do is report a venue's geo refusal as what it is — a refusal naming the
region, not a transport error — so the operator can add the rule.

**Keep a budget with `storage::increment`, reserve first, and never read-then-write.**
Two calls of one agent can run at the same time — a key paying with money is not
limited to one call in flight — so a cap kept as "read the day's total, check,
write the new total" lets both calls see room for the last unit. `increment` is
atomic (compare-and-swap with retries in the host). Take the unit before the
work, refuse and give it back if that passes the cap, and give it back if the
work did not happen; keep it when the outcome is unknown, because an over-count
refuses one request and an under-count lets one past the owner's limit. The
Gmail, Polymarket and Hyperliquid connectors each carry a small `Reservation`
that releases itself when dropped unkept — copy that.

**Report an error by answering, not by exiting.** A run that ends with a
non-zero exit code or a trap is a failed run: its output is discarded, the
caller sees a bare trap message, and the operation fee is refunded. An
operation that could not do what was asked answers `ok: false` with a reason
and exits 0 — the caller gets the reason, and the operation is paid for,
because it ran.

---

## 4. Secrets

A connector reads secrets exactly as any other project does — the model is the
one in `wasi-examples/WASI_TUTORIAL.md` §3c. What trips connectors up is that
three credentials belonging to different people meet in one run: yours, the
caller's, and the agent's.

### 4.1 Your credential (the connector author's)

Your SMTP password, your upstream API key — a credential that belongs to **you**
and is the same for every caller.

Store it under your own account with the accessor of the project the
connector is published as, and name it in the manifest:

```bash
outlayer secrets set --project connectors.outlayer.near/<id> --profile prod '{"BUILDER_KEY":"…"}'
```

```jsonc
// outlayer.manifest
{ "connector_id": "<id>", "author_secrets": { "owner": "you.near", "profile": "prod" } }
```

The worker decrypts that profile into the environment on **every** run of the
connector, next to whatever the call itself names (an agent's own secrets,
§4.2); the call carries nothing. `owner` defaults to the account the project
is published under. The row's access condition is judged against the real
caller, so it is also who may run your connector at all — `AllowAll` for
everyone, a whitelist or DAO role for a circle. A name defined on both sides
refuses the run rather than picking a winner, and so does a manifest that names
a profile nobody stored — a connector written around a credential does not run
without it.

A caller points a call at a credential of theirs through the body's
`secrets_ref`, on a connector as on any project; the author's goes in the
manifest because it is the artefact's, not the call's.

Access to a stored secret is governed on chain by an `AccessCondition`, which is
richer than a list: `AllowAll`, `Whitelist`, `AccountPattern`, `NearBalance`,
`FtBalance`, `NftOwned`, `DaoMember`, `ValidUntil` (admits only before an
instant), `WasmHash` (admits only a run of one exact build), `Predecessor`
(judges the condition it wraps on the account that *called* the contract
rather than the signer), and `Logic`/`Not` to combine them. That is how you
can hand a credential to a class of callers — everyone holding a particular
NFT, every member of a DAO role — without naming them, and how a grant to one
agent is made to lapse on its own: `And[Whitelist[agent], ValidUntil(lease
end)]`.

Every leaf but `Predecessor` is judged on the transaction's signer, so a
contract the owner signs any transaction to is the predecessor when it relays
`request_execution` naming the owner's row — and the owner's own whitelist
admits it. `And[Whitelist[me], Predecessor{Whitelist[me]}]` closes that: a
call is admitted only when the account that called the contract is the owner,
with no contract in between. `Predecessor{Whitelist[dao]}` names the one relay
calls may come through instead. Over HTTPS nothing relays a call, and the
payment key's owner is judged as the caller too. A function-call access key on
the owner's own account signs directly — predecessor and signer are both the
owner — and no condition can see it.

Those class checks ask the chain, one after another, while a shared keystore
waits — so a condition may hold **at most five** of them (`NearBalance`,
`FtBalance`, `NftOwned`, `DaoMember`), and at most sixteen `AccountPattern`
leaves of four kibibytes in all. Naming accounts costs nothing: a `Whitelist`
is answered from the condition itself, at any size.

Decryption happens in the keystore TEE and the plaintext exists only inside the
worker that runs your module. The coordinator never sees it.

### 4.2 The caller's credential (the agent's own)

An agent may have a secret of its own that YOUR connector needs to act on its
behalf — its account on your service, its own upstream token.

The agent asks for it with a header:

```
X-Use-Owner-Secret: 1
```

Nothing is looked up unless the call asks, because most connectors need no
secret and a lookup costs a keystore round trip plus a "not found" that means
nothing.

With the header alone, where it is looked up is not in the request: both the
profile and the owner are the agent's **own account**, taken from the payment
key's row. The secret was stored BY that wallet, so it is owned by the same
account it is named after — which is what makes it unforgeable, since only the
wallet's key can make that wallet sign.

A body `secrets_ref`, when present, is used instead — the same field every
project's callers use. It names any row whose on-chain condition admits the
calling wallet: an owner who stored a credential once under their own account
and whitelisted their agents hands it over this way, and takes it back by editing
the whitelist. The header is the shortcut for the one row an agent need not know
the name of, its own. A reference the contract could never hold a row for — an
account id that is not one, a profile that is not 1–64 bytes or holds an ASCII
character other than a letter, digit, `-` or `_` — is refused at the door
(`invalid_secrets_ref`, 400) rather than queued for a run that would read
nothing; on the on-chain path the contract itself refuses a malformed
`profile` at `request_execution`, before yielding, with the same sentence,
and a malformed `account_id` fails argument deserialisation there.

The header is meaningful only for a key owned by a custody wallet. An ordinary
payment key's holder addresses their own secrets through the body, as always.

### 4.3 How secrets reach your code

As environment variables. Read them with `std::env::var`.

**Locking a secret to one build.** A project's or repository's row carries
across versions — publish v2 and it keeps working. A credential a new build
must *not* inherit — a signing key that *is* the connector's identity, say —
says so in its access condition: a `WasmHash` leaf admits only a run whose
bytes hash to that SHA-256, ANDed with whoever may read the row:

```json
{"Logic": {"operator": "And", "conditions": [
  {"Whitelist": {"accounts": ["alice.near"]}},
  {"WasmHash": {"hash": "<sha256 of the build>"}}
]}}
```

The keystore judges the leaf against the hash the worker measured on the
bytes it is about to run, sent with every decrypt — never a value the call,
the manifest or your guest supplies. A rebuild has a different hash and is
refused with a message naming the build the row is locked to. The row and its
ciphertext stay put: `update_access` moves the condition to the next build
without re-encrypting, so a `PROTECTED_` key generated in the enclave keeps its
value across the releases you approve. From the CLI: `outlayer secrets set
--project … --build <sha256>` to store locked, `outlayer secrets access
--project … --access … --build <new sha256>` to move it. The hash is shown as
**Executed binary** in an execution's details on the dashboard.

Two rules protect you from a caller who tries to impersonate the platform:

**Reserved names are refused at storage time.** `store_secrets` rejects any key
the worker itself injects — `NEAR_SENDER_ID`, `NEAR_USER_ACCOUNT_ID`,
`OUTLAYER_PROJECT_OWNER`, `WALLET_ID` and the rest. You get an error naming the
offending keys.

**And the worker strips them anyway.** Before writing a single system value,
`merge_env_vars` removes every system name from the merged secrets. So whatever
arrives under a system name came from the worker, not from whoever supplied the
secrets — regardless of storage-time checks.

Absent stays distinct from empty: a variable the worker does not set for this
run is *missing*, not blank, so `env::var("OUTLAYER_PROJECT_OWNER").ok()` still
means "no project".

`PROTECTED_` is a reserved prefix for secrets the keystore generates. Manual
secrets cannot use it.

The full list of injected variables, and what each means, is in
[`wasi-examples/WASM_ENV_VARS.md`](../wasi-examples/WASM_ENV_VARS.md).

### 4.4 Who your caller is

`NEAR_SENDER_ID` is the identity the guest acts as. It is injected by the worker
and cannot be chosen by the caller — that is what the two rules above are for.
near.email turns it into the mailbox it sends from; treat it as the account you
are acting for.

`NEAR_USER_ACCOUNT_ID` is who **paid**. The two are the same unless the caller
is an Agent Connect wallet running under a bound account's name, which is opt-in
per call. Bill and attribute against the payer; act as the sender.

### 4.5 Keys of your own: EVM sub-keys

A connector that holds funds on an EVM chain — a venue deposit, a bridge leg —
should not hold them at the wallet's own address, where every other connector
under the same wallet could spend them. It holds them under a **sub-key**: a
distinct secp256k1 key of the same wallet, one per `label`.

From the guest it is four host functions in `outlayer:wallet/api`:

| function | what it does |
|---|---|
| `get-sub-key-address(chain, label)` | the sub-key's `0x` address (empty label = `default`) |
| `evm-sign-typed-data(chain, typed_data_json, label)` | EIP-712 v4 signature |
| `evm-sign-message(chain, message, encoding, label)` | EIP-191 `personal_sign`; `encoding: "hex"` for a pre-hashed digest such as an ERC-4337 userOpHash |
| `evm-sign-transaction(chain, unsigned_tx, label)` | signature over a serialized unsigned transaction, `0x05‖rlp` EIP-7702 preimages included; needs `evm_sign.raw_tx` in the wallet's policy |

The guest names only the **label** (`[a-z0-9][a-z0-9_-]{0,31}` — `trading`,
`bridge`). The worker turns it into the keystore path
`connector.{connector_id}.{label}` — and it does so only for a project
published under the connectors namespace whose verified manifest names
`connector_id` equal to the project's own name. The id is read from the wasm
the worker is running, never from the guest or the task, and tying it to the
curated name is what keeps a hostile artefact from embedding another
connector's id. So a connector reaches its own sub-keys and nobody else's; any
other project has none at all (every label answers `sub_key_unavailable`).

**Every EVM key a guest can sign with is a sub-key.** The empty label is the
sub-key `default`, not the wallet's own key. The address `get-address` returns
for an EVM chain — `wallet:{id}:evm`, where the owner's own funds may sit — is
never signable from inside a module: the worker maps every label, the empty
one included, to a `connector.…` path, so there is no call a module can make
that reaches it. The wallet's own key is signable only from outside, through
the HTTPS wallet API, by the holder of the wallet's credential. A module that
must move the wallet's own funds uses the policy-metered operations
(`withdraw`, `transfer`, `swap`), not a signature.

A wallet-using connector is **HTTPS-only**. The wallet reaches the guest from
the call's credential — a payment key the custody wallet owns, plus
`X-Wallet-Id` — and the on-chain door carries no such thing, so a module that
imports `outlayer:wallet` cannot start from `request_execution` at all. Keep
wallet operations in a connector that is called over HTTPS, and let an on-chain
caller use a different one.

By convention a venue connector uses two labels: `trading` for the account
the venue knows (the key that signs orders) and `bridge` for the EVM address
its funding legs pass through. The path still carries the connector's id, so
`connector.hyperliquid.trading` and `connector.polymarket.trading` are
different keys; the shared names are for the agent's benefit — one learned
connector reads like the next. A label is part of the address: renaming one
after funds have arrived means a new, empty address.

Two things a sub-key is not. It is not a separate authority: the owner's
`evm_sign` policy governs every sub-key exactly as it governs the wallet's own
key, and whoever holds the wallet's API key can sign for any path from outside
the enclave — the isolation runs one way: a connector cannot reach the wallet's
key, the wallet's owner can reach every connector's. And it is not stored anywhere: the address is derived on request,
so the only record of which sub-keys a wallet ever used is the coordinator's
log. Pick labels by purpose and keep them stable — a renamed label is a new
address with an empty balance.

---

## 5. Limits

Four independent mechanisms can refuse a call to you. They are ANDed — every
applicable one must pass — and none of them can raise another.

### 5.1 Price (the contract)

Per operation, in the contract's pricing table, with the author's share and the
account it pays to alongside it. The chain enforces it: `request_execution`
refuses a call that does not attach the operation's exact price.

You do not set this in your manifest. A manifest may state a *recommended*
price; the on-chain one is what is charged.

### 5.2 Operation limits (the coordinator)

`(operation, window, max, who it applies to)`. One primitive for every "no more
than N per period" rule.

* **window** — `day`, `week`, `month`. Rolling from first use, **not
  calendar-aligned**: a calendar month resets for everybody at midnight on the
  1st, which turns a monthly cap into a stampede. "This month" means the 30 days
  since you started.
* **applies** — `everyone`, `unpaid` (no purchased subscription), `covered`
  (calls paid from an allowance — trial and gift included).
* **operation** — exact (`gmail:send`) or a whole-segment wildcard
  (`gmail:*`). No general globbing: `gmail:*` matches
  `gmail:send` and not `gmailx:send`. These are the coordinator's own
  rules, written with the connector id; **in your manifest you write it
  without** — see §5.3.

When one is exceeded the caller is told the number, the period, and how many
seconds until the counter expires — because the window rolls from first use and
nobody can work that out from the outside.

### 5.3 Limits your connector declares about itself

Your manifest may carry `limits`. They are **unioned** with the coordinator's
rules, never compared: since every applicable rule must pass, declaring
something stricter gets you the stricter number and declaring something looser
changes nothing. There is no comparison to get wrong and no drift to detect.

**Write the operation WITHOUT your connector id.** The id is prefixed for you
when the declaration is stored:

```jsonc
// in your manifest
{ "operation": "send:external", "window": "day", "max_count": 3, "applies": "covered" }
// what it becomes, and what the counter is keyed by
"gmail:send:external"
```

Write the prefix yourself and you get `gmail:gmail:send:external`.
Rules are matched exactly, so it caps nothing — and nothing tells you: no error,
no log, no failing call. You would ship believing you had limited yourself. The
id is added rather than accepted so a manifest cannot declare limits about a
*different* connector.

The rest of the name is yours and may be finer than the operation. `send:external`
is not a second operation — it is what a `send` counts as when any recipient is
outside near.email, a distinction only the connector can make.

Use this for a cap that protects something only you know about — mail
deliverability is the canonical case. It travels inside the wasm and is covered
by the on-chain hash, so it holds even where the coordinator's own table does
not.

One sharp edge worth knowing: the numbers in force are the ones the last binary
that **ran** reported, keyed by project rather than by hash. A rollback restores
the old numbers when the old binary next runs, not the moment it is published.

A word the platform does not recognise is read at its **strictest**, not
dropped — an unknown `window` reads as `month`, an unknown `applies` as
`everyone`. Check your own manifest at build time; `connector-probe/build.sh`
shows how.

### 5.4 What the caller's key allows

Independent of anything you declare:

* **scope** — a payment key lists the projects it may call, as `owner/project`
  or `owner/*`. Empty means any project. The wildcard is a whole trailing
  segment only: `owner/pre*` does not match `owner/prefix`.
* **balance or subscription** — a call is paid from the key's money or from an
  allowance. A subscription runs **one call at a time** per key; a second
  concurrent one falls back to money if the key has any, and is refused with
  `call_already_in_flight` (retryable) if it does not. Money-paid calls have no
  concurrency limit and never occupy the subscription's slot.
* **compute** — resource limits per call, clamped to the tier's ceilings.

---

## 6. The owner's page

A connector whose credential a person stores needs a page where they connect it
and look after it afterwards. Every such page meets the same constraints — a
wallet that only opens from a click, a two-step change where the first step
looks finished, state that cannot be read back without a transaction, a reader
who came to change one setting and not to learn about enclaves.

Those constraints are written down as numbered rules at the top of
`app/connect/gmail/page.tsx` in the dashboard, which is the reference
implementation: copy the page and the rules together. The policy form itself is
schema-driven — add `lib/policies/<connector>.ts` and the existing editor
renders it, summarises it as permissions, and turns it into the JSON your
connector reads.

## 7. Testing before you ship

`connectors/connector-probe` exists for exactly this. It is published,
priced, metered and manifested like a real connector, and every operation
reports one fact about the platform rather than doing work:

| operation | what it proves |
|---|---|
| `ping` | a free operation is still a real price: it runs only on a key that can pay |
| `whoami` | both identities the worker injected — who you act as, and who paid |
| `env` | every system variable, present or missing, so one going quiet is a failed probe |
| `secret` | the owner's secret arrived — presence, length and a hash prefix, never the value |
| `burn` | compute costs something |
| `fetch` | your declared host is reachable |
| `forbidden_fetch` | an undeclared host is not, and the refusal comes from the worker |

Copy its shape. In particular copy two habits: it never returns a secret's
value, and it never accepts a host to fetch from the caller. A connector that
fetched a caller-chosen host would be an SSRF gadget with a TEE's network
access; one that echoed secrets would make every test run a leak.

---

## 8. Checklist

1. Write the guest. Dispatch on a top-level `operation` string.
2. Embed a manifest with `connector_id` and every host you need in
   `capabilities.network`. No manifest means no network.
3. Fail the build if the custom section is missing.
4. Publish under the curated namespace.
5. Price every operation on chain, including the free ones — unpriced is
   refused, not free.
6. Decide whose secret you need: yours (`secrets_ref` + an `AccessCondition`) or
   the caller's (`X-Use-Owner-Secret`). Most connectors need neither.
7. Declare a `limits` entry for anything only you know is fragile.
8. Handle errors. Read `NEAR_SENDER_ID` for who you act as and
   `NEAR_USER_ACCOUNT_ID` for who paid; never take either from the input.

## See also

* [`CONNECTOR_DOCS.md`](CONNECTOR_DOCS.md) — writing a connector's documentation: which claim is read from which source, and what a diff forces you to re-check. Hand it to whoever (or whatever) writes the skill and the spec entry
* [`wasi-examples/CONNECTOR_MANIFEST.md`](../wasi-examples/CONNECTOR_MANIFEST.md) — manifest reference
* [`wasi-examples/WASI_TUTORIAL.md`](../wasi-examples/WASI_TUTORIAL.md) — writing and building a WASI guest
* [`wasi-examples/WASM_ENV_VARS.md`](../wasi-examples/WASM_ENV_VARS.md) — every injected variable
* [`skills.outlayer.ai/outlayer-connectors`](https://skills.outlayer.ai/outlayer-connectors/SKILL.md) — the library as an AGENT reads it: the call, the refusal codes, what a call costs, and one line per connector. Every connector publishes its own skill beside it (`https://skills.outlayer.ai/<connector>/SKILL.md`), with a pointer to that URL next to the code; write one when you publish, because an agent that has to infer your operations from prose gets them wrong
* [`connectors/connector-probe/`](../connectors/connector-probe/) — a working connector to copy
