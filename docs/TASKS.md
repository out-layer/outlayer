# Tasks between an agent and its owner

An agent prepares; the owner reads and approves; the agent's run carries it out.

A run of a project, admitted to an owner's secret row, leaves that owner a
**task**: "confirm this email", "show me the bet before it is placed", "give me
your photo". The owner learns of it and reads it in their inbox, with no run
and at no cost, and approves it with one message their wallet signs. The
platform then starts a run of the agent that prepared the task — on the
agent's own payment key, as the agent's own call, within the compute limit of
the run that prepared it — and that run executes the operation the task
names. The owner sends no transaction and pays nothing; nobody runs the agent
but the platform, on the owner's signature. The agent learns the outcome the
next time it asks.

It is one system for the platform. Any WASI project may use it, connectors
among them, and an owner with ten agents reads their tasks in one inbox.

What it is not:

* **Not a paused run.** Nothing waits inside the enclave. A task is a record.
* **Not a run of the owner's.** The owner signs; the run that acts is the
  agent's, paid by the agent's key, and bounded by the run that prepared it.
  An agent's call that was worth $1 of compute is carried out for $1 at most.
* **Not a script the owner is made to run.** A task names the operation that
  answers it and carries no arguments for it. The project's code decides what
  happens.
* **Not a replacement for a service's own confirmation.** A bank's approval
  rules stay where they are.

## Using it in a project

1. Say so in the manifest (`wasi-examples/CONNECTOR_MANIFEST.md`):

   ```json
   "tasks": true
   ```

   The run that carries a task out is an HTTPS call of the agent's, and the
   owner opens tasks for a new device with a direct call of their own
   (`tasks_unlock`): a `callers` block that shuts either door beside `tasks`
   does not parse.

2. Build on the SDK with the `tasks` feature:

   ```toml
   outlayer = { version = "0.2", features = ["tasks"] }
   ```

3. Open a task where the owner must be asked, and answer the agent
   `awaiting_owner`:

   ```rust
   use outlayer::tasks::{self, Display, FieldKind, WrittenBy};

   let opened = tasks::confirm(
       Display::new("Send an email")
           .list("To", &message.to, WrittenBy::Agent)
           .field("Body", FieldKind::LongText, &message.body, WrittenBy::Agent),
       "confirm",                 // the operation the owner's approval runs
       &serde_json::to_vec(&message)?, // handed back to it; never shown
       policy_json.as_bytes(),    // the policy the task is made under
   )
   .open()
   .map_err(|e| e.refusal())?;
   return Ok(tasks::awaiting_owner(&opened));
   ```

4. Write the operation the task names. The platform runs it on the owner's
   approval, as the agent's own call: it takes the answer, acts, and reports:

   ```rust
   let answer = tasks::answered_for("confirm", &input, policy_json.as_bytes())
       .map_err(|e| e.refusal())?;
   let message: Message = serde_json::from_slice(&answer.state)?;
   check_against_the_policy_as_it_is_now(&message)?;
   let sent = send(&message)?;
   tasks::report(&answer.id, sent.to_string().as_bytes()).map_err(|e| e.refusal())?;
   ```

5. Hand the rest to the dispatcher. It answers `task_status`, `task_cancel`,
   `task_delete`, `tasks` and `tasks_unlock` alike in every project:

   ```rust
   if let Some(answer) = tasks::dispatch(operation, &input) {
       return answer;
   }
   ```

6. A connector prices every operation it serves, these among them — by one
   rule. **A task is paid for when it is prepared.** The operation that opens
   a task is charged its own price, as it is when it acts at once, and nothing
   comes back if the owner says no or the task runs out. The operation that
   answers a task, and the five the dispatcher serves, are priced at zero: the
   action was paid for by whoever asked for it, and an owner pays nothing to
   say yes. The run the platform starts on an approval is admitted only when
   its operation is priced zero — a priced one fails the task
   `operation_priced` — and its compute is paid by the agent's payment key,
   as any call of the agent's is, up to the compute limit of the run that
   prepared the task. A key that cannot pay for it fails the task
   `preparer_key_unavailable`; nothing is charged to the owner.

`connectors/tasks-probe` is a project that does nothing else, and
`connectors/gmail-connector` is a connector whose `send` asks the owner when
their policy lists it under `confirm`. How a connector puts an action behind
the owner's confirmation: [CONNECTOR_TASKS.md](CONNECTOR_TASKS.md).

## Whose task, and who may do what

The **owner** of a task is the owner of the secret row the run named and the
keystore opened. The **preparer** is the account that made the run. Both are
the worker's facts, from the job and the keystore: no function of the host
interface takes an account.

The run that **answers** a task is the preparer's, started by the platform
on the owner's approval: it is admitted with the consent sealed in the task
— the preparer's payment key, wallet, identity binding and compute limit, as
the preparing run had them — and the host refuses the answer in any other
run (`not-the-preparer`), and in the preparer's own run without the owner's
signature over this task, this hash and these words (`approval-invalid`).
A task opened by that run is the next **turn** of the answered task's
conversation: it carries the answered task's `thread`, and it is the same
agent's — the inbox shows it from that agent, the agent's `mine` and `status`
list it, and it counts in that agent's share and under its mute. A turn is
opened whatever the owner's row says of that agent now: one the row no
longer admits is still the preparer of a turn in the owner's own inbox,
which muting that agent and deleting its waiting tasks clears. A run that
answered tasks of more than one conversation opens none: `open` is refused
`internal`. A run that answered nothing — or whose every answer was refused
— opens in a conversation of its own.

| The run is | It may |
|---|---|
| the project's, made by an account the owner's row admits **by name** | open a task for that owner; read, cancel and delete its tasks — those it made and the turns of its conversations; read their outcomes |
| the one the platform started for an approved task: the preparer's, on the preparer's key | answer that task, report its result, and open the next turn of its conversation |
| the project's, made by the owner | open tasks for themselves; open their waiting tasks for a new device (`tasks_unlock`) |
| the project's, admitted by a row open to everyone, to a pattern, or to holders of a token or a role | run; `open` is refused `not-granted-by-name` |
| the project's, made by another agent of the same owner | nothing of the first agent's tasks |
| another project's | nothing of this project's tasks |
| any run that names no row, or whose row did not open | nothing: `no-owner` |
| any run a contract relayed — the account that called OutLayer is not the account that signed; a meta-transaction is not one, it is the call of the account that signed the delegate action | nothing: `relayed` |

A run uses tasks only when the account that called OutLayer is the account
that signed: the owner's wallet calling the contract itself, or a call over
HTTPS. A contract the owner signs any transaction to can call OutLayer in the
owner's name; such a run is signed by the owner and is not the owner's act,
so it opens, reads and answers nothing.

A call over HTTPS is made as the account whose payment key pays for it, and a
task is opened over HTTPS only: the consent to carry out the owner's answer
is a payment key — the run that carries it out is paid by that key — so a
run on chain is refused `no-payment-key` at `open`. No key answers a task by
calling: a key of the owner's account is not the preparer, and the preparer's
own call carries no approval. The run that answers is started by the platform
and by nothing else.

"By name" is a `Whitelist` that lists the caller on the path that admitted
them. A dated grant — `And[Whitelist, ValidUntil]` — is by name while it lasts.

As with a bot in a messenger, nobody writes to a person who has not let them,
and the owner silences whom they please: they mute an agent or a project in
the inbox, and delete its waiting tasks at once. What is being acted on, and
the outcomes kept, stay.

## The task

| Part | Holds |
|---|---|
| `id` | the run that made it and its number within that run: `<call id>-<n>`, or `req-<request id>-<n>` for a run on chain |
| `display` | what the owner is shown: a title and fields |
| `files` | what the owner is given to open beside the fields: an attachment, a document. Each is named in the envelope by name, type, size and hash, and handed back when the task is answered |
| `answer_by` | the operation the owner calls, and what they supply with it: nothing, text, or a reference to a file |
| `state` | bytes of the project's own, sealed beside the task and handed back when it is answered. The prepared action lives there. Never shown |
| `policy_hash` | the hash of the policy the task was made under |
| `build` | SHA-256 of the build that made the task: the code the owner's proof names, and the build the run that answers must be of |
| consent | sealed beside the envelope, never shown: the preparing run's payment key (its nonce), wallet, whether its identity was bound, and its compute limit — what the run that carries the task out must be admitted with. The store keeps the same facts in the clear as the task's **voucher**, from which the platform starts that run |

The task key is under the master of the vault the owner's row is bound to,
and under the default master for a row bound to none: what a vault seals, it
seals with its own key, tasks included. The store records the vault beside
each task (`vault` in the inbox's list), so what a vault's owner did is
known as the vault's.
| `thread` | the id of the first task of the conversation; a turn keeps the conversation's preparer |
| life | 24 hours at most; a project may ask for less |

Everything but `state` is one document, the **envelope**, written once in a
fixed order. `task_hash` is the SHA-256 of its bytes. The owner's page hashes
the bytes it opened and the owner's answer names that hash, so what was shown
is what is acted on.

### What the owner is shown

A title of 80 characters and up to 12 fields. Each field is a label, one of six
kinds — `money`, `account`, `address`, `text`, `long_text`, `list` — its values,
and whose words they are: the project's (an amount it computed) or the agent's
(a body, a memo).

Every value is drawn as plain text. No markup is interpreted, no link can be
pressed, no image is loaded. What refuses the task: control characters,
characters that are not drawn or that reorder or hide text, more than four
combining marks in a row, a text made only of spaces. A `long_text` may hold
line breaks and tabs, and an emoji written with its selector and its joiner is
drawn as that emoji. A file's name is no path, neither begins nor ends with a
space or a dot, and is of one file of the task; its type is `type/subtype`. The host checks all of it in `open`, whatever the project was
built with.

A `long_text` holds 50000 characters, and is shown whole. A file is listed by
its name, type and size and given to the owner as a download: the page opens
it with the task's content key, holds it to the size and the hash the envelope
names, and saves it — it draws no file in itself, and saves every one as plain
bytes whatever type the task says it is.

### States

| State | Means |
|---|---|
| `open` | waits for the owner |
| `approved` | the owner approved; the platform queued the preparer's run, named in `run`, which has not taken the answer yet |
| `answering` | that run took the answer and acts |
| `done` | that run ended well and the project reported |
| `failed` | the run could not be started, did not start, refused the task, or ended any other way. `failure_reason` says which: `preparer_key_unavailable`, `operation_priced`, `operation_unknown`, `operation_limit_reached`, `wallet_unresolved`, `queue_unavailable`, `run_not_started`, or `run_refused:<reason>` with the host's reason — `hash-mismatch`, `answer-invalid`, `not-the-preparer`, `approval-invalid`, `expired`, `void`, `unreadable`, `unavailable`, `not-found`, `unreported` |
| `rejected`, `cancelled` | the owner said no; the preparer withdrew it |
| `expired` | past its life |
| `void` | the policy changed since it was made, or the run that answered was of another build of the project than the one that made it; found when it is answered |

Each move is made once. A task never returns to `open`: a run that failed may
have acted in part, so the owner sees `failed` and the agent prepares a new
task if the work is still wanted. A task `approved` for thirty minutes without
a run taking its answer, and one `answering` for thirty minutes without a
report, are ended `failed` by the platform (`run_not_started`, and the run's
status).

A task that leaves `open` loses what it showed at once — the sealed copy and
every device's copy. Its outcome is kept 30 days.

### Limits

| Limit | Value |
|---|---|
| open tasks addressed to one owner | 20 |
| tasks one run opens | 5 |
| a task's life | 24 hours |
| what the waiting tasks of one owner hold together | 64 MiB |
| files of one task | 10, and 6 MiB together: what one call carries |
| `state` | 256 KiB |
| the envelope | 256 KiB |
| what the owner supplies, the note beside their approval, or the reason they reject with | 8 KiB sealed each; the owner's page takes 5000 bytes of text |
| of them, from one preparer, `open` and `approved` together | 10: an eleventh is refused `inbox-full` (`preparer_full` at the store) |
| a result left for the preparer | 16 KiB |

## What is sealed, and who reads it

The coordinator stores a task and opens none of it.

| Part | At rest | Who reads it |
|---|---|---|
| the envelope | twice: sealed under a key of the enclave, and under a content key wrapped to each of the owner's devices | the owner, on a signed-in device; the host |
| the files | under the task's content key, each bound to the task and to its place | the owner, on a signed-in device; the project's code, when the task is answered |
| `state` | sealed under the key of the enclave | the project's code, when the task is answered |
| what the owner supplies, the note beside their approval, the reason of a rejection | encrypted by the owner's page to the task's reply key | the project's code, in the run that answers; the preparer's next run |
| the owner's approval — the signature, the key, the nonce, the minute | in the clear | the coordinator at the door; the host in the run that answers, which verifies it again |
| the result | sealed under the key of the enclave | the preparer's run |
| who asked whom, through which project, of what kind, when, the state | readable by the coordinator | the owner in a session; the preparer; the coordinator |

```text
project key (keystore)   HMAC-SHA256(master, "task-key:v1:{project_uuid}:{owner}")
  task key               HMAC-SHA256(project key, "task:" || id)
    seal key             XChaCha20-Poly1305, bound to the task's id
    reply key pair       a P-256 key pair; the public half goes out with the task
content key              32 random bytes per task; AES-256-GCM
```

The project key comes in the run's one request to the keystore, beside the
row, and only beside a row that opened. It is held by the host and never given
to the guest. A run of another project holds another key.

What a browser handles is what WebCrypto has: ECDH on P-256, HKDF-SHA256 and
AES-256-GCM.

## The proof

Before the owner's page offers the button, it checks that the task was made by
a published build of its project:

| Step | Held by |
|---|---|
| the run that made the task is attested: a quote Intel signed, from an enclave whose measurements are approved on chain, committing to the fields it is published with | Intel, and the contract |
| the attested run was a run of the task's project, made by the task's preparer | the attestation |
| the build that ran is a version of that project on the contract, published as a wasm | the contract |
| what the run answered hashes to the attestation's `output_hash` | the attestation |
| that answer names the task's id with `task_hash` — the hash of the bytes the page opened | the page |

So a project's answer has to name the task it opened: `tasks::awaiting_owner`
is that, put wherever the answer has room for it. A turn puts it beside its
result, for the next task.

The run's input and its answer are served to the owner by
`GET /inbox/tasks/{id}/origin` for a call over HTTPS, each as the bytes its
attestation's `input_hash` and `output_hash` are the SHA-256 of; a request on
chain carries both in its transaction. The
attestation is public (`GET /attestations/by-call/{call_id}`,
`/by-request/{request_id}`).

A step that could not be run — the chain or the API did not answer — is "not
checked", never "does not hold". The owner may approve past a proof that does
not hold or was not checked, by saying so: the approval is still refused in
the enclave unless the hash it names is that of the task sealed there, so a
task written into the store can be shown and cannot be acted on.

The run that carried a task out is named by `run` once there is one, and its
attestation is public too: the page holds it to the task — a call of the
preparer, of the task's project, of the build the task names.

## The owner's session and devices

The owner signs **one message** with their wallet (NEP-413, recipient: the
OutLayer contract):

> Sign in to OutLayer as `alice.near`. Device key: `p256:…`. Valid until `2026-10-29T12:00:00Z`.

The device key is the public half of a key pair the browser made and keeps
non-extractable: the page uses it and cannot read it. The statement opens a
session on that device until its deadline — 30 days at most, not extended —
and stays stored whole.

An account has **five devices in force** at most, each with a session and a
key of its own: the owner's browser, their phone and an app of theirs read the
same inbox. One sign-in more retires the device signed in longest ago and
deletes the copies it was given; that device is answered 401
`session_replaced` from then on, and the dashboard says so on it. The owner
sees their devices in the inbox's settings, each with the wallet key that
signed it in, and withdraws any of them.

Before the host encrypts a task to a device it checks the statement itself:
the account, the deadline, the signature over the sentence rebuilt from its
three facts, and that the key that signed is a full-access key of the owner's
account **on chain**. A row written into the store by anyone but the owner's
wallet is a row the host refuses. While the chain cannot be asked, no task is
opened.

| The owner | Reads |
|---|---|
| on a device signed in when the task was made | at once, free |
| on a new device, or after a session ran out | after signing in there and one call of the project's `tasks_unlock`, which writes the copies for the devices now in force |

A device is a convenience, never the only copy: every task is sealed for the
enclave as well, so a lost device loses nothing.

Signing out, or withdrawing a device from another, ends its session and stops
new copies for it. So does removing from the account the wallet key that signed
the device in, or cutting it down to calling functions: the chain is asked
again every ten minutes, and a session ends when the chain has said twice
that its key is gone. A device
lost together with the wallet key that signed it in is cut off for certain by
removing that key from the account: every statement it signed stops holding.

| Whoever holds | Can | Cannot |
|---|---|---|
| the coordinator's database | see who was asked by whom, of what kind and when; delete a task | read what a task shows; add a device of their own; act on a task |
| a session's token | list tasks as ciphertext; reject and delete | read a task without the device's key; act on a task |

## The inbox API

Inside a session (`Authorization: Bearer os_…`). The routes, their bodies and
every refusal are in the API spec under **Inbox**.

| The owner wants to | Route | Needs |
|---|---|---|
| sign in, sign out | `POST`, `DELETE /inbox/session` | a signed statement; the session |
| know what waits, read it | `GET /inbox/tasks` | the session, and this device's key |
| open a file of a task | `GET /inbox/tasks/{id}/files/{n}` | the session, and this device's key |
| check the proof: the run, what it was asked, what it answered | `GET /inbox/tasks/{id}/origin`, and the run's attestation | the session |
| reject, with a reason | `POST /inbox/tasks/{id}/reject` | the session |
| delete one, or all | `DELETE /inbox/tasks/{id}`, `DELETE /inbox/tasks` | the session |
| mute an agent or a project, see who is muted, unmute | `POST`, `GET`, `DELETE /inbox/mutes` | the session |
| see the devices signed in, withdraw one | `GET /inbox/devices`, `DELETE /inbox/devices/{id}` | the session; for another device, the owner's signature too |
| be told at a URL, see it, remove it | `PUT`, `GET`, `DELETE /inbox/webhook` | the session; to name or remove, the owner's signature too |
| approve | `POST /inbox/tasks/{id}/approve` | the session, and the owner's signature over the task |

In the dashboard the mutes, the devices and the webhook are on the inbox's
settings screen, `/inbox/settings`.

A session's token lists, rejects and deletes; what a stolen token could do
beyond that is bounded by one more signature. Withdrawing another device of
the account, and naming or removing the webhook, take the owner's wallet:
one NEP-413 signature over a sentence that names the action and the minute,
`Confirm in OutLayer as alice.near: withdraw the device <id>. At <time>.`,
made from the owner's click, good for ten minutes, once. The webhook's URL
is named in the sentence by its SHA-256, so the wallet shows no address.
Without it the answer is 403 `confirmation_required`.

**Approving** is the same signature over the task:

> Approve in OutLayer as `alice.near`: task `<id>` with hash `<64 hex>` and supply `<64 hex>`. At `<time>`.

The hash is `task_hash`, the SHA-256 of the envelope bytes the page opened;
the supply is the SHA-256 of `{"note":<base64|null>,"supplied":<base64|null>}`
over what the owner wrote — their answer to an `input` task (purpose
`answer`), and a note for the agent beside any approval (purpose `note`),
each sealed by the page to the task's reply key — so the owner's words are
under the owner's signature, not merely beside it. The body of
`POST /inbox/tasks/{id}/approve` is `{task_hash, approval: {at, public_key,
signature, nonce}, supplied?, note?}`. The coordinator rebuilds the sentence
from the session's account, the path's id and the body, verifies it, spends
the nonce, and moves the task `open → approved` with the run it then
queues; the enclave rebuilds it again from the sealed envelope and the
run's input, and takes an approval up to ten minutes ahead of its clock and
up to thirty behind. A `confirm` task takes no `supplied`; an `input` task
takes one. The answer is `{id, state, run}`, with `failure_reason` when the
run could not be started and the task is `failed` at once. A key removed
from the account between the door and the run passes the door — the chain's
word is kept five minutes, as at sign-in — and is refused in the enclave.

A refusal is `{"error": sentence, "reason": code, "terminal": bool}`. Nothing
waiting is `{"tasks": []}`; no session is 401 `session_required`, with no count
and no list, and the session of a device that a later sign-in retired is 401
`session_replaced`; a store or a chain that did not answer is 503
`upstream_unavailable` with `Retry-After`. A refusal is never an empty list.

What waits for approval on a wallet is listed inside the same session, to the
owner of the wallet's policy only
(`GET /wallet/v1/pending_approvals_by_pubkey`). One approval is told by its id
to whoever holds it (`GET /wallet/v1/approval/{id}`).

### Events

An owner who named a URL is sent `task_created`, `task_approved` (with the
`run` queued for it), `task_answered`, `task_failed` (with `failure_reason`)
and `task_expired`, through the sender the wallet's webhooks use, with
`X-Wallet-Id: owner:<account>` and `X-Webhook-Signature`: the HMAC-SHA256 of
the body, in hex, under a secret of the owner's own. The secret is made when
the URL is named and told to the owner once, in the answer to that call and in
the dashboard; naming a URL again makes a new one.
A body says who asked whom, of what kind and when, and links to the inbox. It
carries nothing of what the task shows.

The URL is an HTTPS URL on a public host, with no credentials in it. The
sender follows no redirect, and connects only to a public address. The URL
stays in force when the session that named it ends; the inbox says when it
was named and by which session, and warns of one named elsewhere.

## The host interface

`outlayer:tasks`, specified in `worker/wit/deps/tasks.wit`. Every function
answers `result<_, task-error>`, where the error is a `reason` to branch on and
a `message` for a person. None traps. Absence is a value: `mine` with nothing
is `ok([])`.

| Function | Who | Does |
|---|---|---|
| `open(request)` | preparer | makes the task |
| `mine()`, `status(id)` | preparer | its tasks — a turn is the preparer's of its conversation — or one of them; `status` also reads a task this run opened |
| `cancel(id)`, `delete(id)` | preparer; or the run that opened the task | withdraws, deletes |
| `answered(id, hash, operation, policy, approval, supplied, note)` | the preparer's run the platform started for the task | verifies the owner's approval over this task, this hash and these words, and takes the answer; hands back `state`, the files, `supplied` and `note` opened |
| `report(id, result)` | the same run | leaves the result for the preparer |
| `unlock()` | owner | writes the copies for the devices now in force |

`open` seals the run's consent into the task — its payment key, wallet,
identity binding and compute limit — and sends the same facts to the store as
the voucher. `answered` holds the run it is in to that consent before it
looks at the signature: another key, wallet, identity, or more compute than
the preparing run was allowed is `not-the-preparer`. The refusals a run
meets before the task moves are reported to the store when the run ends, and
a task refused at that door is `failed` with `run_refused:<reason>`.

| `reason` | A project answers | When |
|---|---|---|
| `not-declared` | `tasks_not_declared` | the manifest does not say `"tasks": true` |
| `no-owner` | `no_owner` | no row named, the row did not open, or no project |
| `relayed` | `relayed` | a contract made the run: the account that called is not the account that signed |
| `not-granted-by-name` | `not_granted_by_name` | the row admitted the run by a rule that does not list the caller |
| `muted` | `muted` | the owner muted this agent or this project |
| `inbox-full` | `inbox_full` | a limit of open tasks, or of what they hold together |
| `run-limit` | `task_run_limit` | this run opened as many tasks (5), or made as many calls of the interface (100), as one run may |
| `display-invalid` | `display_invalid` | what is shown is outside the bounds; the message names what |
| `too-large` | `task_too_large` | `state`, `policy`, the files, the envelope or a result |
| `life-too-long` | `task_life_too_long` | a life asked beyond the maximum |
| `no-payment-key` | `task_no_payment_key` | `open` in a run on chain: a task is opened over HTTPS, with the payment key that will pay for the run that carries it out |
| `not-found` | `task_not_found` | no such task of this project, owner and preparer |
| `not-the-owner` | `not_the_owner` | `unlock` in another account's run |
| `not-the-preparer` | `not_the_preparer` | `answered` or `report` in a run that is not the one the platform started for the task: another account, another payment key, another wallet, another identity, or more compute than the preparing run was allowed |
| `approval-invalid` | `task_approval_invalid` | the owner's signature does not verify over this task, this hash and these words, is by a key that is not a full-access key of the owner's account, is too old or too far ahead, or the task was never approved |
| `hash-mismatch` | `task_hash_mismatch` | the hash named is not the task's |
| `answer-invalid` | `task_answer_invalid` | another operation than the one the task names; or what was supplied, or the note, is not what was asked, or does not open |
| `closed` | `task_closed` | answered, rejected or cancelled already; or approved, and this run is not the one started for it |
| `expired` | `task_expired` | past its life |
| `void` | `task_void` | the policy changed, or another build than the one that made the task answers it |
| `unreadable` | `task_unreadable` | a sealed copy that does not open. The message is `decryption failed` |
| `unavailable` | `task_store_unavailable` | the store or the chain did not answer. The one a caller repeats later |
| `internal` | `task_internal_error` | a fault of the platform's own, which a repeat does not mend. Where a task's id is named, an earlier run of the same call took it: the task is among the caller's. Also `open` in a run that answered tasks of more than one conversation |

## Tests

| What | Where | Run |
|---|---|---|
| the task key, "admitted by name" | `keystore-worker` | `cargo test` |
| the store, sessions, the inbox, events | the coordinator, against PostgreSQL | `TEST_DATABASE_URL=… cargo test owner_tasks` |
| the host interface, against a store and a chain that a test can tamper with | `worker/src/tasks` | `cargo test --lib tasks::` |
| the probe through the executor to an in-process store and RPC | `worker/tests/tasks_probe.rs` | `cargo test --release --test tasks_probe` |
| the page's side against the host's, on shared vectors | `tests/lib/tasks_page.test.mjs` | `node --test` |
| the approval end to end on testnet: the agent prepares, the owner's page signs, the agent's run acts | `tests/tasks_e2e.sh` | `--apply`, through a keyed RPC |
