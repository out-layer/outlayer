# Project manifest

A module runs inside a keys-bearing TEE and may talk to the internet and hold
its author's credential. Both are declared by the module itself, in a manifest
embedded **inside the wasm**. Any project may carry one; for a connector it is
mandatory, and `connector_id` is what makes the network section fail-closed.

## Where it lives, and why there

The manifest goes in a wasm custom section named `outlayer.manifest`.

That section is covered by the wasm's SHA256, which the contract records for the
version and the worker checks before executing. Nobody — not us, not the
coordinator operator, not the author after publishing — can change what a
published version is allowed to reach without changing its hash, and changing
its hash means publishing a new version the user has to move to.

The alternatives are weaker:

| Source | Anchored by | Problem |
|---|---|---|
| **custom section** | the on-chain wasm hash | none; works for `WasmUrl` sources too |
| `manifest.json` at a git ref | nothing | a force-push moves what the ref points at while the ref stays the same |
| a row in the coordinator's database | nothing | an operator can widen the allowlist with one `UPDATE`, silently |

**The custom section is the only source.** A `manifest.json` at the repository
root is not read, and must not become a second source: it would make the row
above true of the code as well as of the table — anchored by nothing, with the
network policy moving whenever somebody pushed. A wasm without the section
declares nothing, and a CONNECTOR without the section reaches nothing.

Nothing is lost by that. `connector-probe/build.sh` fails the build when the
section is missing, so the omission is caught at the author's desk; and anything
published as a `WasmUrl` — an IPFS CID, say — has no repository to read anyway,
so the embedded section is the only option there.

## What goes in it

```jsonc
{
  "connector_id": "near-email",
  "display": { "name": "near.email", "author": "zavodil.near" },
  "operations": ["send", "send_with_attachment", "list", "read"],
  "capabilities": {
    "network": ["mail.near.email"]
  },
  "author_secrets": { "owner": "zavodil.near", "profile": "prod" }
}
```

The names in `operations` must be exactly the strings your guest dispatches on
and exactly the ones priced on chain — see the next section.

| Field | Read by the worker | Meaning |
|---|---|---|
| `connector_id` | **yes** | Stable identity. Its presence also opts the project into fail-closed allowlist enforcement, wherever it is published. Never contains a version — the version is a property of the code, not of who the connector is; a version here would make every release a different connector to everything that keys off the id — its prices, its limits, its stored secrets. |
| `capabilities.network` | **yes** | The outbound allowlist. Exact hostnames, case-insensitive, **no implicit subdomain wildcard**: `example.com` does not permit `evil.example.com`. List every host you need. Absent on a project without `connector_id`: egress stays unrestricted, as for a wasm with no manifest at all. |
| `operations` | no | Documentation, and a cross-check against the price list. |
| `limits` | **yes** | Caps this connector declares about itself. Unioned with the coordinator's own rules — every applicable one must pass — so a declaration can only ever tighten. |
| `author_secrets` | **yes** | The author's own credential, for any project: the row `owner` stored under the accessor `Project(<this project id>)` and `profile`, decrypted into the environment on every run next to the caller's. `owner` defaults to the publishing account. The row's access condition is judged against the real caller, so it is who may run the project — `AllowAll` for everyone, a whitelist or DAO role for a circle. A name on both sides, or a profile nobody stored, refuses the run; a name the caller's row carries and the author never stored is added to the environment as the caller's — store every name your code reads, so no caller can supply it. A run with no project (a `Repo` source executed directly) cannot hold one. See `WASI_TUTORIAL.md` §3c and `docs/CONNECTORS.md` §4.1. |
| `signing_keys` | **yes** | ed25519 keys the module signs with, by `path`. The keystore derives each for the run, bound to the caller and to the project or the exact code; the module reaches them only through the `outlayer:signing-keys` host functions. Any project may declare them. See `signing_keys` below. |
| `display` | no | For the dashboard. |
| `describe` | no | What each operation does and takes, for the developer page (`app.outlayer.ai/connectors/<id>`) — see the next section. |

### `describe`: the operations, for a reader

```jsonc
"describe": {
  "summary": "Send mail from the owner's own address, to the recipients the policy allows.",
  "operations": {
    "send": {
      "class": "write",
      "doc": "One message, policy-checked, then sent.",
      "params": [
        {"name": "to", "type": "string | string[]", "required": true, "doc": "Bare addresses, no display names."},
        {"name": "subject", "type": "string", "required": true},
        {"name": "attachments", "type": "Attachment[]", "doc": "{filename, content_type, data: base64}."}
      ]
    }
  }
}
```

The dashboard's page for a connector is rendered from this block of the
ACTIVE version's wasm — the coordinator reads the section out of the bytes it
serves to workers — so what a developer reads is what the deployed code
answers to, and a page with its own copy of the list cannot exist to drift.

| Field | Meaning |
|---|---|
| `summary` | One sentence: what an agent can do with the connector. |
| `operations.<name>` | One entry per operation, keyed exactly as `operations` lists them. |
| `class` | `read` or `write` — the same word the price list uses. |
| `doc` | One sentence, what the operation does. |
| `params[]` | Every field the operation reads from the input, except `operation` itself. `type` is prose for a developer (`string`, `number`, `decimal string`, `string[]`, `object`), `required` defaults to false, `doc` is optional. |

`build.sh` holds it to the code: every operation the guest dispatches is
described and nothing else is; every parameter is a field of an input struct
(`Input`, `…Input`) or a name the code reads off the input (`input.get("…")`).
It does not check that a parameter belongs to THAT operation, nor `required`:
those stay the author's to get right, against the code.
An operation added to the code and not described, or described and gone,
fails the build; a parameter's owner and `required` are the author's to keep.

### The words `limits` may use

```jsonc
"limits": [
  { "operation": "send:external", "window": "day", "max_count": 3, "applies": "covered" }
]
```

| Field | Allowed | Anything else |
|---|---|---|
| `operation` | your operation, **without your connector id** | see below |
| `window` | `day` \| `week` \| `month` | read as **`month`** |
| `applies` | `everyone` \| `unpaid` \| `covered` | read as **`everyone`** |

`unpaid` is everyone without a purchased subscription; `covered` is everyone
whose calls come out of an allowance, trial and gift included.

**Do not write your connector id in `operation`.** It is prefixed for you when
the declaration is stored, so `send:external` becomes `near-email:send:external`
— which is what the counter is keyed by. Writing the prefix yourself produces
`near-email:near-email:send:external`, and rules are matched exactly: it would
match nothing, cap nothing, and say nothing about it. The prefix is added rather
than accepted so that a manifest cannot declare limits about a *different*
connector.

The rest of the name is yours, and it can be finer than the operation itself —
`send:external` is not a second operation, it is what a `send` counts as when
any recipient is outside near.email. That distinction is one only the connector
can make, which is why the key is built from the request rather than from the
price list.

**A word we do not recognise is read at its strictest, not dropped.** That is
deliberate, and it is the second version of this rule: the first one skipped
what it could not parse, and when the audience names changed, every manifest
already published kept its old word and quietly stopped declaring anything at
all. Nobody noticed, because nothing failed.

Being read strictly cannot hurt anybody but this connector's own callers — a
declaration is unioned with the coordinator's rules and every applicable rule
must pass, so there is no value here that could widen a limit. Check your own
manifest at build time; `connectors/connector-probe/build.sh` shows how.

### `signing_keys`: keys the module signs with

```jsonc
"signing_keys": [
  {"path": "records", "type": "ed25519"},
  {"path": "votes", "type": "ed25519", "caller": "predecessor"},
  {"path": "payouts", "type": "ed25519", "vault": "vault.alice.near"}
]
```

Each entry is a key the module signs with. The keystore derives it inside the
TEE from what the run IS — how its code is run, and its caller — never from
anything the module says. The module never holds a key: it names one by `path`
and calls the `outlayer:signing-keys` host interface
(`worker/wit/deps/signing-keys.wit`):

| Function | Answers |
|---|---|
| `public-key(path: string, vault: option<string>) -> result<list<u8>, string>` | the 32-byte ed25519 public key |
| `sign(path: string, vault: option<string>, message: list<u8>) -> result<list<u8>, string>` | a 64-byte RFC 8032 signature over the raw message bytes — no prehash, no prefix. At most 65536 bytes of message; sign a digest to cover more |

`vault` names the key's declared vault exactly: `none` for a key declared
without one, `some("<vault>")` for a key declared with that vault. Any other
combination, an undeclared `path`, and a message over the limit are an `err`
carrying the reason, never a trap. A module that imports the interface and
declares no key gets an `err` for every path.

| Field | Allowed | Meaning |
|---|---|---|
| `path` | `[a-z0-9][a-z0-9_-]{0,31}`, unique in the list | The key's name and an input of its derivation. The same path gives the same key for as long as its binding holds; another path is another key. Renaming a path loses the key, any address made from its public key, and every signature checked against it. |
| `type` | `ed25519` | The only type. |
| `bind` | `project` (default) \| `wasm` | How the code must be run to get the key, and what the key belongs to besides the caller. There is no repository binding. |
| `caller` | `signer` (default) \| `predecessor` | Which account of the run the key belongs to: the transaction's signer (the payment key's owner over HTTPS), or the account that called the contract. A segment of the derivation, so the two never derive one key. |
| `vault` | a NEAR account id | `project` keys only: derive from that vault's master instead of the default one. |

At most 3 keys. A key with an unknown field is refused, not read with the field
dropped: a misspelled `vault` would derive from the default master, a
misspelled `bind` would bind to the project, a misspelled `caller` to the
signer. A `type`, `bind` or `caller` value outside its list is refused the same
way.

**The caller is part of every key**, and `caller` says which account of the
run it is. The platform sets both accounts from the job; neither the code nor
the input can.

* `signer` (the default): the account in `NEAR_USER_ACCOUNT_ID` — the
  transaction's signer on chain, the payment key's owner over HTTPS. Any
  contract the signer ever transacts with can start a run under the signer's
  key with input of its own — an `ft_transfer_call`, a DAO proposal, a wallet
  contract's callback all execute as the signer — so a module must never treat
  its input as the signer's intent.
* `predecessor`: the account in `NEAR_PREDECESSOR_ID` — the account that
  called the contract: the DAO or wallet contract itself when one relayed the
  call, the signer when none did, and the signer over HTTPS. The key is that
  contract's, not the signer's; on a payment through `ft_transfer_call` it
  binds to the token contract. A run that carries no predecessor is refused
  before it starts.

Both are legitimate; the module author chooses per key. A signer key and a
predecessor key for one account are two keys. A run with no caller account is
refused: the worker's placeholder for a missing account is refused by name,
before it could pass as an account id.

**Keys are issued strictly by how the code is run:**

| `bind` | Issued only to | The key belongs to | A new version of the code | The same key for |
|---|---|---|---|---|
| `project` (default) | a run through a project whose version is a `WasmUrl` version | the project's on-chain uuid + the chosen caller | keeps the key | that caller, running any version of that project |
| `wasm` | a direct run from a wasm URL, with no project | the code's sha256 + the chosen caller | gets new keys | that caller, running that exact binary directly |

**Who checks what.** The worker reads the run off the job the coordinator gave
it — its `project_id`, its resolved code source, its signer and predecessor —
never off the module, and sends the job's `user_account_id`, `predecessor_id`,
`executed_wasm_sha256` and `project_id` with the key request. The request has no
field saying how the run was started: a `project_id` makes it a project run,
none a direct run. The keystore takes those four fields on the trust of the
worker's TEE attestation, exactly as it does for secrets, and verifies on chain
only what the chain can answer: for a project run, that the sha256 the worker
measured on the running code is a `WasmUrl` version of that project and that
the project exists with the owner its id names; for a `vault`, that it belongs
to that owner. The worker checks every declared `bind` and `caller` against the
run before any secret is decrypted; the keystore checks them again. One key
that does not match refuses the whole run before it starts.

A GitHub-sourced run is never issued signing keys — neither a project version
built from a repository nor a repository run directly. Through a project, the
keystore sees it: the contract's version for the build's hash has a GitHub
source, or there is none. Directly, only the worker sees it — it holds the
resolved code source, while the keystore holds nothing but the hash of the
bytes — so the worker refuses a direct GitHub build before any request is made.
A manifest that reaches the worker declaring keys on such a run refuses it; a
module that reaches the worker with no declaration runs, and every signing call
answers `err`.

So one run never holds both kinds. The manifest is part of the wasm, so a
binary that declares `project` keys runs only through a project, and one that
declares `wasm` keys runs only directly: declare the one `bind` that matches how
the module will be run.

**`project`** belongs to the project's on-chain `uuid`, minted once at
`create_project`, never to its `owner/name` id. So the key survives code
upgrades — every later version signs with the same key, and whoever publishes
versions of the project decides what they sign — and it survives a transfer of
the project: the id changes, the uuid stays, and the keys stay with it. A
project deleted and created again under the same name is another project with
another uuid, and so other keys. Another project, or another caller, gets
another key.

**`wasm`** belongs to the code, not to a deployer: anyone who runs the exact
binary directly gets keys for their own callers. So the code must never decide
WHAT to sign from secrets, environment variables or configuration — whoever runs
the binary controls those, and a user lured into calling someone else's run of
the same code would sign under that runner's configuration. Decide what to sign
from the input and the code alone.

**`vault`** derives a `project` key from that vault's master instead of the
default one. The vault must belong to the project's owner: it is a direct
sub-account of the owner (`vault.alice.near` for `alice.near/app`), and its
contract's `parent` is that owner. A vault not named directly under the owner
is refused on the two names alone, before any chain read. A vault that is
missing, unreadable, not the owner's, unfunded or not loadable refuses the run;
the default master is never used in its place. A `wasm` key cannot name a
vault: code has no owner to own one.

**NEP-413 and the implicit account.** `sign` takes raw bytes, so a module can
produce a NEP-413 (NEAR `signMessage`) signature: it signs
`sha256(borsh(2^31 + 413 as u32 LE) ++ borsh(payload))`, 32 bytes. The key's
public key, in lowercase hex, is a NEAR implicit account, so the signature
verifies against that account with no registration. The copyable code and a
Python verifier are in [`signing-key-probe`](signing-key-probe/README.md)
(`sign_nep413`).

That also makes the key a wallet nobody governs: it can sign NEAR transactions
for its implicit account, and Solana ones for the same public key. Funds sent
there are controlled only by the code, outside every wallet policy. Do not hold
money on a signing key. EVM is not supported: it needs secp256k1.

**Never sign caller-supplied bytes or digests verbatim.** For the same reason:
a signature over bytes the caller chose is a signature over whatever those bytes
are — a transaction that empties the implicit account, an authorization, a
message the account never meant. Sign only messages the module composes itself,
from fields it has parsed and checked, under a fixed prefix or structure of its
own; an input that asks for a signature over raw bytes is refused.

**Where the keys live.** The keystore derives them in the same request that
decrypts the run's secrets and hands them to the worker for that one run. They
live in that run's memory only — never in the environment, stdin or a log — and
are dropped with it. The master never leaves the keystore.

**Refused before the code runs:**

* a WASI P1 module that declares keys — only a P2 component imports host
  interfaces;
* more than 3 keys, a `path` of the wrong shape or declared twice, an unknown
  field, a `type`, `bind` or `caller` outside the lists above;
* keys declared on a GitHub-sourced run, when the manifest reaches the worker;
* a `project` key on a run with no project; a `wasm` key on a run through a
  project;
* a `predecessor` key on a run that carries no predecessor;
* a project run whose running code is not a `WasmUrl` version of that project,
  or whose project does not exist on the contract or is not owned by the
  account its id names;
* a `vault` on a `wasm` key; a `vault` not named directly under the project's
  owner (refused by name, before any chain read); a `vault` that fails any
  check above;
* a run with no caller account — the worker's placeholder for a missing account
  is refused by name;
* a worker or keystore without signing-key support.

## How a request names its operation

**One field, the same for every connector: a top-level `operation` string.**

```json
{ "operation": "send", "to": "someone@example.com", "subject": "…" }
```

Over HTTPS that object is the `input` of an ordinary call; on chain it is
`input_data`. Either way it is the same bytes, and four readers take the
operation out of them:

| Reader | What it does with it |
|---|---|
| the contract | prices the call on chain, and requires that exact price |
| the coordinator | bills it and picks which limit rule applies |
| the worker | refuses to run a connector call that names none |
| your guest | dispatches on it |

That is why the format is fixed rather than yours to choose. The contract prices
the call out of the request itself, and it cannot be taught one request shape
per connector — so a per-connector rule would mean the chain could not price
anything. One field means one value: nothing to bind to anything, and nothing
that can drift apart.

**Fail-closed, and identically everywhere.** Absent, blank, not a string,
nested, or spelled anything else — all refused, before your code runs. None of
them defaults to an operation, because a defaulted operation is a defaulted
PRICE, and the cheapest one is what an attacker would pick.

Two constraints come with it, and they are part of the format:

* a priced project's request must be a **JSON object**;
* on chain it must be at most **10 KB** — the contract parses it, and parsing is
  linear in the body with the caller's gas paying for it. A connector that moves
  more than that takes a reference, not the bytes.

If your callers insist on their own spelling, translate it at your own edge
before the request reaches us. It does not change what we price.

### What does NOT go in it

**Prices.** The price of an operation lives **on chain**, in the contract's
`project_pricing` table, and nowhere else. A connector author who could set
their own price would set it to zero and burn our workers; and the chain
enforces it — `request_execution` refuses a call that does not attach the
operation's exact price — so a second copy baked into a published wasm could
only ever disagree with the one that decides. A manifest may state a
*recommended* price; the on-chain one is what is charged.

**The author's share** lives there too, per operation, next to the price it
splits, along with the account it is paid to. Same reason: it is what the
contract divides a payment by.

**Anything granting a capability.** Declaring `connector_id` only ever
*restricts* a project — it opts it into an allowlist. Being callable at all
comes from the coordinator's connector registry and the calling key's scope,
never from something the code says about itself.

## Fail-closed

A connector whose manifest cannot be read — missing, not valid JSON, larger than
64 KB, or present but declaring no `network` — gets an **empty allowlist**: no
outbound network at all.

That is deliberate. The other choice is a connector with a broken manifest
quietly keeping the run of the internet from inside a TEE that holds keys, and
nothing anywhere would say so.

`"network": []` and no `network` key are different things and stay different: an
empty list is a connector saying it talks to nobody; a missing key is one that
says nothing about the network. For a connector both end at the same place; for
an ordinary project the first is enforced and the second is not.

## Embedding it (Rust)

Put the manifest next to `Cargo.toml` and reference it from a static:

```rust
/// The connector manifest, embedded in a custom section so it is covered by the
/// wasm hash the contract records for this version.
///
/// `#[used]` keeps the linker from dropping a static nothing references.
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");
```

That is all — `cargo build --target wasm32-wasip2` carries it through, and
`wasm-tools component new` keeps it in the core module the component embeds. The
worker reads either shape.

Verify before publishing:

```bash
wasm-tools print target/wasm32-wasip2/release/your-connector.wasm \
  | grep -c 'outlayer.manifest'      # must be at least 1
```

## After publishing

The version's wasm hash is what the contract stores, so a manifest change is a
new version. On an ordinary project a caller may keep pinning the old one with
`version_key` and keeps its old allowlist with it. A **connector** is different:
it always runs its active version and a pin is refused (`invalid_version_key`),
so a new active version — and its allowlist and declared limits — applies to
every caller at once. To take a version out of service entirely, switch the
active version and `remove_version` it on chain.

## Getting listed as a connector

The manifest makes a project *enforced*; it does not make it *curated*.

Every connector is deployed under one account — `connectors.outlayer.near`, or
`connectors.outlayer.testnet` — so its project id is `{namespace}/{id}` and it
is called like any other project:

```
POST /call/connectors.outlayer.near/{id}
```

There is no separate connector endpoint and no alias. While a short name and the
thing it ran could differ, the same code had two doors and every check on one
had to be mirrored onto the other.

Which ids are curated is a list in the coordinator's source
(`src/handlers/connector_registry.rs`), so adding a connector is a code change
and a deploy. That is on purpose: a list in the database would let one `UPDATE`
make a different project curated, and every subscription in existence could then
be spent on it, at our expense, with no review.
