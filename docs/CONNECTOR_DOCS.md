# Writing a connector's documentation

A procedure, meant to be handed to an agent along with a connector's manifest
and source — or, for an update, along with the diff. It is not a style guide:
the rule throughout is that **every claim is read from a source, and the source
is named here**. Documentation that was written from memory of how a connector
works is the kind that is wrong in the one place a reader relies on.

## 1. The three artefacts, and what belongs in each

A connector carries three pieces of writing. They overlap in subject and not in
purpose, and duplicating between them is how they start disagreeing.

| artefact | reader | answers |
|---|---|---|
| `https://skills.outlayer.ai/<id>-connector/SKILL.md` | an agent deciding what to call | what to do, in what order, what a refusal means and whether to retry it, and how to get its owner through setting the thing up |
| the `Connectors` tag and `/public/connectors` in `vendor/api-spec` | a person surveying the platform | what a connector IS, which exist, where to read about one |
| `connectors/<id>/README.md` | whoever opens the code | how it is built, published and priced; what its author must store |

The skill is the one that gets long. The spec stays generic on purpose: it
describes the shape of a connector call once, not each connector's operations —
those live on chain and in the manifest, and a third copy in a fourth repository
would be the copy that lies.

## 2. Sources of truth

Never write any of these from reading prose, including this document's examples.

| claim | read it from |
|---|---|
| which operations exist | the `match op` dispatch in `src/main.rs` **and** `operations` in `manifest.json` — they must agree, and `build.sh` refuses the build when they do not |
| an operation's parameters | the `Input` struct in `src/main.rs`; a field that is `Option` is optional, and `#[serde(default)]` says what absent means |
| what an operation costs | the chain: `get_project_pricing` for the project. Not the price script — that is the writer, and a row may have been changed since |
| the author's share | the same price rows (`developer_share_bp`) |
| daily caps the connector declares | `limits` in `manifest.json` |
| which hosts it may reach | `capabilities.network` in `manifest.json`; absent means unrestricted, which is a claim worth making explicitly |
| the secret key names a caller must store | the `*_ENV` constants in the source, not the README that mentions them |
| whether it carries a credential of its own | `author_secrets` in `manifest.json`, and whether that row exists on chain |
| the exact words of a refusal | the `format!` that produces it |
| whether a refusal is worth retrying | the code path that returns it — see §4 |
| what a run withholds or seals when its output lands on chain | the connector's output path: which field is sealed, under which label, and what decides (`OUTLAYER_EXECUTION_TYPE`); for Gmail, `src/seal.rs` and `policy_view` in `src/main.rs` |
| what an owner does to connect, and what it stores | the setup page's own source — for Gmail, `app/connect/gmail/page.tsx` in the dashboard repository: its screens in order, the keys and the access rule it writes, and every error string it can render |

For an update, the diff decides what to re-read. §5 lists which change forces
which re-read.

## 3. What the skill must contain

In this order, because it is the order an agent needs them.

1. **What the connector does, and what it cannot do.** The second half matters
   more: an agent that knows the mailbox cannot be read will not plan to read it.
2. **The call shape**, with `{api_host}` and `{connectors_account}` as
   placeholders and the network table beneath. Never a hardcoded mainnet
   example — somebody will be on testnet and will not be able to derive it.
3. **Where the credential comes from**, and the exact request to make of its
   owner. Link the shared recipe in
   `https://skills.outlayer.ai/outlayer-connectors/SKILL.md` rather than
   restating it.
4. **How to walk the owner through setting it up.** Wherever a person has to do
   something themselves — a consent screen, a page, a wallet — the agent is the
   only one in the conversation who knows what is about to happen, and the owner
   is the one who stops halfway and reports that it is broken. Read the setup
   page's own code and write down, in the order the owner meets them:
   * **what they need before starting** — an account, funds, the right network.
     A setup finished on the wrong network is discovered much later, by a refusal
     that mentions none of this.
   * **every screen, and what each one does** — including the ones nobody clicks.
     An unattended step that looks like a hang is where people reload and lose
     the thing being set up.
   * **the moments where nothing has happened yet**, said plainly. A page that
     stops before a signature is not stuck, and a reader who knows that waits.
   * **what it means, in the owner's terms**: what is stored, who can read it,
     what it cannot do, how to undo it. Only claims the code supports.
   * **the error strings the page itself can show**, and what each means. The
     owner will paste one back, and matching it is faster than reasoning about it.
   * **what is still left to do afterwards** — the grant, usually. A finished
     setup is not yet a working agent, and an agent that stops at "connected"
     leaves the owner believing they are done.

   The third-party screens the owner meets on the way belong here too — a
   provider's consent, an "unverified app" warning, an account limit. They are
   not ours, and an unexplained warning is exactly where a careful person stops.
5. **Start here**: the free `status`, and a table of what its answers mean —
   including the half-configured states, which read as failures and are not,
   and what the same call answers on chain, where a field may be withheld.
6. **Each operation**: its parameters, what it returns, and what it costs.
7. **What the policy or the caps permit**, stated as permissions and not as
   restrictions. See §4.
8. **Costs**, including that a run which started is charged even when the
   outside service then refuses it.
9. **Refusals**: the string, what it means, and whether retrying can ever help.

## 4. The rules that keep it honest

Each of these is here because its absence has already cost somebody a working
session.

**Say whether a refusal is terminal.** An agent's next move is decided by this
and by nothing else. `rate_limited` and `api_disabled` arrive as the same HTTP
status from the same service, and one clears by waiting while the other never
does — an agent told to wait on the second retries until its budget is gone.
Every row in the refusal table says which kind it is.

**State a default by what it permits, not by what it restricts.** A policy whose
fields are all unset reads, to anyone, as "nothing is allowed". In the Gmail
connector it means the opposite: any recipient, any number of messages. Write the
permission: *"an empty policy allows sending to anyone; `max_attachment_kb` is
the only field that denies by default."*

**Name the limit that actually binds.** A trial key holds a dollar and lives a
week, and neither is what stops an agent — the daily connector quota does, at
about ten calls. Publishing the dollar as the budget invites arithmetic that is
wrong by an order of magnitude. If two limits exist, say which one is reached
first.

**Do not put an optional thing in a mandatory-looking template.** `X-Wallet-Id`
in a call example, with no word that it is optional, sends an agent looking up a
wallet id it never needed. Mark optional headers, or leave them out.

**A counter counts attempts.** Where a quota or a cap is incremented before the
limit is compared, refusals spend it too. Say so: otherwise "retry until it
works" looks free and is not.

**Placeholders for anything network-specific**, with the table. A connector's
account differs between networks and the two never mix.

**What a run returns on chain is public for ever.** An answer over HTTPS is
seen by its caller; an answer on chain is written into the transaction and is
readable by anyone, always. So a connector withholds or seals there what it
would say freely over HTTPS — the Gmail policy, which names people, comes back
only sealed to a `reply_pubkey` the caller passed, and without one the fields
are simply absent. Say which part of an answer that is, what the caller passes
to get it, and how it is opened. An agent that reads an on-chain answer and
finds a field missing must know that is by design and what to do, not report a
broken connector.

## 5. On an update: what the diff forces

Read the diff, then re-read only what it touched — and re-read it from the
source, not from the previous version of the documentation.

| the diff touches | re-read and re-check |
|---|---|
| `manifest.json` `operations` | the operation list in all three artefacts; `build.sh` enforces the agreement, so run it |
| the dispatch in `src/main.rs` | the same, plus whether a new operation needs a price row on chain before it can be called at all |
| the `Input` struct | every operation's parameters; a field that changed from required to optional changes what a caller may omit |
| `manifest.json` `limits` or `capabilities.network` | the caps and the reachable hosts; an added host is a claim about what the connector may now talk to |
| `manifest.json` `author_secrets` | whether the connector now needs a credential of its own, and whether the row exists on both networks |
| any `format!` producing an error | the refusal table, including whether the new refusal is terminal |
| the price script, or a price row on chain | the cost table — and check the chain, because the script may not have been run |
| the setup page (`app/connect/<id>/…`, another repository) | the walkthrough of §3.4: the steps in order, the keys and access rule it writes, the error strings. Its diff is one to go and read: nothing in the connector's own repository moves when that page changes, and the skill goes stale silently |

**A changed manifest changes the artefact's hash**, so the connector must be
republished before the documentation is true of what is deployed. Documentation
that describes an unpublished build is worse than none: it reads as current.

## 6. Before publishing

* `./build.sh` in the connector — it already refuses a build when the manifest,
  the dispatch and the README disagree about the operations, and it verifies the
  manifest's vocabulary and the injected system variables.
* Read the prices off the chain and compare them with the cost table.
* Call the connector's free `status` on the network you documented, and check
  that its answer matches what the skill says that answer means.
* For anything the documentation claims a refusal does, find the `format!` that
  produces it and check the words match.
* Open the setup page and go through it as its owner would. Every screen the
  skill promises should appear in that order, and every error string it quotes
  should exist in that page's source.

## See also

* [`CONNECTORS.md`](CONNECTORS.md) — the model these documents describe
* [`wasi-examples/CONNECTOR_MANIFEST.md`](../wasi-examples/CONNECTOR_MANIFEST.md) — the manifest's fields
* [`skills.outlayer.ai/outlayer-connectors`](https://skills.outlayer.ai/outlayer-connectors/SKILL.md) — the shared half every connector's skill links to instead of restating
