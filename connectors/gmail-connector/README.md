# gmail-connector

An agent sends mail from the owner's own Gmail address, under a policy the owner
stored. The credential never leaves the enclave and never appears in an answer.

It **only sends**. The credential carries the single scope `gmail.send`, which
authorises sending and nothing else — not reading the mailbox, not even reading
back which address it belongs to. So this connector cannot see a single message
the owner has, and an agent gets nothing out of the mailbox, by construction. A
message goes without a `From` header and Gmail fills in the connected account
(verified against a live mailbox).

The agent-facing documentation is the skill,
<https://skills.outlayer.ai/gmail-connector/SKILL.md>. This file is the other
half: how the thing is built, published and priced, and what its author holds.

## Why the REST API and not SMTP

The executor gives a guest no sockets at all: TCP, UDP and name lookup are off.
So SMTP cannot be spoken from inside the enclave whatever credential one holds,
and an app password is of no use here. The manifest allows exactly two hosts:
`oauth2.googleapis.com` for the token and `gmail.googleapis.com` for mail.

## Operations

| `operation` | class | what it does |
|---|---|---|
| `status` | read | whether the credential works (it fetches an access token), the policy — every member it holds, `confirm` among them — and the caller's own sends today |
| `send` | write | `to`, `cc`, `subject`, `body`, `attachments` — policy-checked, then sent; or, when the policy lists `send` under `confirm`, left as a task for the owner and answered `awaiting_owner` |
| `confirm` | write | run by the platform on the owner's approval, as the agent's own call, with `task_id`, `task_hash`, the owner's `approval` and their sealed `note`: sends the message the task holds, under the policy the task was made under |
| `task_status`, `task_cancel`, `task_delete` | | a task this caller made, by `task_id`: where it stands, withdraw it, delete it |
| `tasks` | read | the tasks this caller made for this owner |
| `tasks_unlock` | write | the owner's own call: opens the waiting tasks for a device that was not signed in when they were made |

### A send the owner confirms

With `"confirm": ["send"]` in the policy, `send` checks the message against the
policy and sends nothing: it leaves a task for the owner of the row and answers

```json
{"status": "awaiting_owner", "task_id": "…", "task_hash": "…", "expires_at": 1790000000, "link": "https://app.outlayer.ai/inbox/…"}
```

which is a success — the agent did its part. The owner reads the message in
their inbox (who it goes to, the subject, the body, the attachments by name and
size) and approves it with one message their wallet signs; the platform then
runs `confirm` as the agent — on the agent's own payment key, within the
compute limit of the call that prepared the message — and that run sends it.
The agent learns the outcome from `task_status`. The message waits sealed,
and `confirm` sends exactly it: nothing in the task says what to do on a yes.

What the owner is shown is what is sent, so a message to be confirmed is one
that can be shown whole: a body of at most 50000 characters, attachments of at
most 6 MiB together and ten in number. The attachments wait as the task's
files: the owner's page lists each by name, type and size and gives it to the
owner to open. A message over these is refused `display_invalid` or
`task_too_large` and never shown in part.

**The rules at `confirm` are the rules the message was prepared under.** The
policy's bytes are part of the task, and a task made under another policy is
refused `task_void`. What can differ between preparing and confirming is the
day's count and Google's answer. The host admits `confirm` only in the run the
platform started for the task — the agent's, on the agent's key — and only
with the owner's signature over the task's id, its hash and what they wrote:
any other call is refused `not_the_preparer` or `task_approval_invalid`.

**What a refusal does to the task.** The message is inside the task and is
handed over only with the owner's answer, so the answer is taken first and the
message is sent after; a task whose answer was taken never returns to `open`.

| refused | the task | the refusal |
|---|---|---|
| before the answer is taken: no `task_id` or `task_hash`, a policy absent or unreadable, anything the host refuses the answer for (`task_not_found`, `not_the_preparer`, `task_approval_invalid`, `task_hash_mismatch`, `task_answer_invalid`, `task_store_unavailable`, `task_closed`, `task_expired`, `task_void`) | stays as it was in the run; the platform ends it `failed` with `run_refused:unreported` (a refusal of the connector's own, which the host never saw) or `run_refused:<reason>` (one of the host's) | as it is |
| after: a state that is not a message, the day's count, the credential, building the message, Google's refusal of the send | ends `failed` | its own code, and a sentence ending "The task is closed: to send this message, prepare it again" |
| after the message left: the result could not be left for the agent | ends `failed` | its own code, and "The message WAS sent (Gmail message …) and the task is closed without its result: do not prepare it again" |

**What `confirm` answers.** The run the platform starts is an HTTPS call, so
it answers what a send answers, with `status` and `task_id`. On chain
(`OUTLAYER_EXECUTION_TYPE` is anything but `HTTPS`) an answer is the output of
a transaction and stays public, so there it carries `status`, `task_id`,
`message_id`, `thread_id`, `attachments` (a count), `sent_today` and
`remaining_today`, and nothing that names a person or a subject. What is
reported to the task is whole either way, the owner's `note` with it: the
host seals it for the agent, which reads the recipients and the subject from
`task_status`.

A direct `send` answers the same way: whole over HTTPS, and on chain the
same five members. A refusal, which is an answer too, names a recipient by its
place in the list (`recipient 2 of 3`) and never by its address.

### `status` on chain: the policy leaves only sealed

The output of an on-chain run is written into the transaction and is public
for ever, and the policy names the people the owner's agent may write to. So
`status` takes an optional `reply_pubkey` — a secp256k1 public key in hex, 33
bytes compressed as `eciesjs` gives it — and, given one, answers with the policy
**sealed to that key** in
`policy_sealed` (base64); the open part says only `{"present": …, "sealed":
true}`. Without a key: over HTTPS the policy goes in the clear, as the transport
already is; on chain (`OUTLAYER_EXECUTION_TYPE` is anything but `HTTPS`) the
fields are withheld and the answer says how to ask.

The seal is the pair near.email runs on: the `ecies` crate here, `eciesjs` in
the browser — secp256k1 ECDH → HKDF-SHA256 → AES-256-GCM, in a format the two
libraries keep compatible with each other. A key that is not a point on the
curve is refused, and a malformed one is refused before Google is asked for
anything. The dashboard's `openReply` opens it; a golden vector shared by
`src/seal.rs` and the dashboard's `test/ecies.test.mjs` pins the two sides to
each other. This is how the connect page shows an
owner their current policy: one `request_execution` from their own account,
naming their own row.

`to` and `cc` take one address as a string or several as an array, and every
entry must be a **bare** address — `name@example.com`, no display name, no angle
brackets, ASCII only. A display name is the one place a second recipient can hide
from a policy check (`victim@evil.com, <ok@good.com>` is two addresses to Gmail
and one to a check that looks inside the brackets), so the only form accepted is
the one whose checked value is the value sent. A string is never split on
commas: a comma makes it a malformed address, not a list.

## Where it is published

| network | project | state |
|---|---|---|
| testnet | `connectors.outlayer.testnet/gmail` | live |
| mainnet | `connectors.outlayer.near/gmail` | live, same bytes as testnet |

The active version, its source URL and the prices are on chain and are the only
place to read them from:

```bash
near view outlayer.testnet get_project '{"project_id":"connectors.outlayer.testnet/gmail"}' --networkId testnet
near view outlayer.testnet get_project_pricing '{"project_id":"connectors.outlayer.testnet/gmail"}' --networkId testnet
```

## The credential

One value is enough, and the owner never handles it: the **refresh token**,
`GMAIL_REFRESH_TOKEN`. The OAuth client that completes it at run time is this
connector's own, held as its author secret (below), so nothing else has to be
stored.

An owner who brings their own Google OAuth app stores three values instead —
`GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `GMAIL_REFRESH_TOKEN` — and **theirs
wins**: when both are present the caller's client is used and nothing of ours
enters that run. The names are deliberately not the author's: a key defined by
both the author and the caller refuses the run.

The refresh token stays in the enclave; what leaves is one request to Google for
an access token, which is cached in project storage — keyed by a digest of the
credential, so a replaced credential never inherits the previous one's token —
until shortly before it expires.

### Connecting an account

<https://app.outlayer.ai/connect/gmail>, one Google consent and one transaction.
The page exchanges the authorisation code on the server (the client secret cannot
ship in a bundle), then the **browser** seals the refresh token to the keystore's
public key and stores it with `store_secrets`:

| | |
|---|---|
| accessor | `Project(connectors.outlayer.{testnet,near}/gmail)` |
| profile | `gmail` |
| access | `Whitelist[the connecting account]` |
| keys | `GMAIL_REFRESH_TOKEN`, and `GMAIL_POLICY` as `{}` |

The empty policy is consent to send with nothing narrowed — see below. The owner
grants an agent by adding its payer account to that whitelist, and the agent
names the row:

```bash
outlayer secrets access --project connectors.outlayer.testnet/gmail --profile gmail \
  --access whitelist:you.testnet,<agent-wallet-account>@2026-12-31
```

```json
{"input": {"operation": "send", "to": "…"},
 "secrets_ref": {"account_id": "you.testnet", "profile": "gmail"}}
```

A date after an account makes that grant lapse on its own; dropping the account
from the whitelist takes it back. The ciphertext never moves.

One row holds the credential and the policy, and it is the owner's: an agent
is admitted by name in its access condition and stores nothing of its own.

When Google later refuses a refresh, the answer says `credential_expired` and
that retrying will not help, because it will not: connect the account again.

## The author secret

`manifest.json` declares `author_secrets.profile = "author"`, and `build.sh`
refuses a build without it. The row holds this connector's own OAuth client:

| key | what it is |
|---|---|
| `GMAIL_OAUTH_CLIENT_ID` | the client id of the Google app behind `app.outlayer.ai/connect/gmail` |
| `GMAIL_OAUTH_CLIENT_SECRET` | its secret |

Stored under accessor `Project(connectors.outlayer.{testnet,near}/gmail)`,
profile `author`, by the namespace account that owns the project. Its access
condition is the connector's admission gate — `AllowAll`, since anyone may use
the connector — and a **declared but unstored** profile refuses every run of the
project, so it must exist on each network the connector is published to.

The same Google Cloud project must have the Gmail API enabled. When it is not,
Google answers 403 and the connector says `api_disabled` and that retrying will
not help — distinct from the throttle that arrives with the same status.

## Policy (`GMAIL_POLICY`)

```json
{
  "recipient_domains": ["example.com"],
  "recipients": ["boss@other.org"],
  "max_per_day": 20,
  "max_recipients": 5,
  "max_attachment_kb": 2048,
  "subject_prefix": "[agent]",
  "confirm": ["send"]
}
```

This is the point of the connector rather than handing an agent a token. An agent
that can send from a real person's address can phish in their name, so the owner
says who may be written to and how much, and the connector enforces it inside the
enclave before anything reaches Google.

Fail-closed at the edges only: with **no** `GMAIL_POLICY` nothing is sent, and a
policy this build cannot parse — an unknown field included — refuses sending too.
Within a policy that exists, every field is a narrowing: absent means permitted.
`{}`, which the connect page writes, therefore allows any recipient, any number
of messages, any number of addresses per message. The exception is
`max_attachment_kb`: without it the agent may not send files at all, because
silence about attachments is not permission. `recipient_domains: ["any"]`, or
naming neither list, means anywhere. `subject_prefix` is added once when it is
missing, so a recipient can tell agent mail from its owner's. `confirm` lists
the operations that need the owner — `send` is the one there is; a name that is
not an operation to confirm makes the policy unreadable.

`max_per_day` is the owner's own cap on a runaway agent, counted per agent in
UTC days, and it is optional. The mailbox is the owner's and how much it
sends is theirs to decide; the manifest's `send` and `confirm` limits of 500 a
day per calling wallet are a technical ceiling against a loop, set below what
Google itself allows an account, not a quota. An attempt that ceiling refuses
still counts toward it.

**The cap counts direct sends and confirmed sends separately.** A run reads
and writes the storage cell of the account that made it and no other — no
storage function takes an account — and every record is sealed under a key
derived for that account. Both runs that send are the agent's: a direct
`send`, and the `confirm` the platform starts on the owner's approval. So
there are two counts, both in the agent's cell:

| count | record | whose cell | written by |
|---|---|---|---|
| the sends an agent makes itself | `gm:sends:<day>` | the agent's | the agent's `send` |
| the sends the owner confirmed for an agent | `gm:sends:<day>:confirmed` | the agent's | the agent's `confirm`, run on the owner's approval |

`max_per_day` bounds each count for each agent. Under one policy an agent's
sends are all of one kind — `confirm` lists `send` or it does not — so the cap
is exact; on a day the owner switches `confirm` on or off, an agent can send up
to the cap directly and up to the cap confirmed. Each count is one for every
owner the agent sends for. `status` reports the caller's own sends as
`sent_today`.

Each count lives in project storage, in UTC days. A message's
place is **reserved atomically before it is sent** and given back if the send
does not happen — the way the platform reserves money before a call runs — so two
calls at once cannot both take the last place, and a message Google refused costs
nothing from the owner's budget. (It still costs the caller the operation fee,
which is charged before the run.)

## Build

```bash
./build.sh
```

Checks that the artefact carries the `outlayer.manifest` section, that the
manifest's operations are exactly the ones the code dispatches on, that the limit
words are ones the platform knows, and that `author_secrets.profile` is declared.
Prints the SHA-256 to publish.

## Publish

```bash
OUTLAYER_NETWORK=testnet outlayer upload target/wasm32-wasip2/release/gmail-connector.wasm \
  --receiver outlayer.testnet
near call outlayer.testnet add_version \
  '{"project_name":"gmail","source":{"WasmUrl":{"url":"<the URL>","hash":"<the sha256>","build_target":"wasm32-wasip2"}},"set_active":false}' \
  --accountId connectors.outlayer.testnet --deposit 0.1 --networkId testnet
near call outlayer.testnet set_active_version \
  '{"project_name":"gmail","version_key":"<the sha256>"}' \
  --accountId connectors.outlayer.testnet --networkId testnet
```

Added inactive first so the previous version keeps serving while the URL is
checked; rollback is one more `set_active_version`.

## Prices

```bash
CONTRACT=outlayer.testnet OWNER=owner.outlayer.testnet ./set-prices.sh testnet
```

Sets the on-chain price row — `send` $0.01, everything else free, no author
share, since the connector is ours — then tells the coordinator to re-read it. A
message the owner confirms is paid for once, by the agent that asked for it. The admin token
and the coordinator URL come from the main repo's `scripts/.env`. The coordinator
charges from its cached copy, so a row nobody refreshed is a price nobody charges.

## Tests

`cargo test` covers the address parser, the policy, the day's counter, the
translation of Google's refusals, what a message to be confirmed keeps and
shows, what refuses before and after the owner's answer is taken, what
`confirm` answers on chain and off it, that `status` reports every member of
the policy, and the seal — including the golden vector the
dashboard's test opens. The live suite is
`tests/gmail_delegation_e2e.sh` in the main repo: it sends real mail through the
whitelist route and needs the owner's keychain, an agent's payment key and a
recipient.

## Layout

| file | what it is |
|---|---|
| `src/main.rs` | the operations, the input shape, `status` and `send` |
| `src/confirm.rs` | a send the owner confirms: the task, the `confirm` the platform runs on their approval, what it answers on chain |
| `src/oauth.rs` | refresh token to access token, cached; Google's refusals translated |
| `src/gmail.rs` | the send call, with Google's errors turned into what to do about them |
| `src/mime.rs` | building an RFC 2822 message |
| `src/policy.rs` | the owner's rules, address parsing, the day's count |
| `src/seal.rs` | sealing the policy to a caller's `reply_pubkey`, for answers that land on chain |
| `src/store.rs` | sealed records in the caller's storage cell, and the atomic counter |
