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
