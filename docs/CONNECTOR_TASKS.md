# Owner confirmation in a connector

How a connector puts an agent's action behind its owner's confirmation. The
model — tasks, the inbox, the host interface, who may do what — is in
[TASKS.md](TASKS.md); how a connector is built is in
[CONNECTORS.md](CONNECTORS.md). This document is the pattern a connector
follows on top of both. The reference implementation is
[`connectors/gmail-connector`](../connectors/gmail-connector/) (`src/confirm.rs`,
`src/policy.rs`, `src/main.rs`); [`connectors/tasks-probe`](../connectors/tasks-probe/)
exercises every corner of the interface and acts on nothing.

## 1. What confirmation is

The agent calls an operation that would act — send a message, place an order,
pay. When the owner's policy asks for it, the connector checks the call as it
would before acting, and instead of acting it seals the exact action inside a
task for the owner of the row and answers the agent `awaiting_owner`. The
owner reads the task in their inbox and says yes with one message their
wallet signs; the platform then starts a run of the agent that prepared the
task — the connector's `confirm`, on the agent's own payment key, within the
preparing run's compute limit — which carries out the sealed action and
nothing else. The agent learns the outcome from `task_status`.

Every `write` operation of a connector's own is confirmable: the operations
its `describe` block classes `write`, except `confirm` itself and the SDK's
`task_cancel`, `task_delete` and `tasks_unlock`. The owner chooses which ones
in the policy's `confirm` member. The default is none: a policy without
`confirm` acts as it always does.

## 2. The policy member

```json
{ "recipient_domains": ["example.com"], "max_per_day": 20, "confirm": ["send"] }
```

`confirm` is a list of operation names, typed as a serde enum of the
connector's confirmable operations. A name that is not one of them — a read
operation, a misspelling, another case — does not parse, and a policy that
does not parse refuses the connector's writes like any unreadable policy.
From `connectors/gmail-connector/src/policy.rs`:

```rust
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    // … the connector's other members …
    /// The operations that need the owner. Absent or empty: none. Reported by
    /// `status` as the policy holds it, `null` when the policy has none.
    pub confirm: Option<Vec<Confirmable>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmable {
    Send,
}

impl Policy {
    pub fn confirms(&self, operation: Confirmable) -> bool {
        self.confirm.as_ref().is_some_and(|listed| listed.contains(&operation))
    }
}
```

One variant per confirmable operation, spelled as the operation is spelled.
Code branches on the variant, never on a string.

**Deciding per call: rules.** A list of operations asks about every call of
them. A connector whose writes differ by what they carry — an amount, a rail,
a payee — may instead read a `rules` member: a list of `{when, then}`, `then`
one of `allow`, `ask`, `refuse` (a serde enum), `when` the operation and
conditions the connector declares, each a typed field under
`deny_unknown_fields`. The first rule that matches decides; with none
matching the call runs as the rest of the policy allows. Rules are asked last,
of a call every other check passed, so a rule never widens the policy. A
condition the operation does not carry (an amount on a cancellation) makes the
policy unreadable, like a misspelt field. `ask` then follows this document
exactly as a listed operation does. The reference is
[`connectors/mercury-connector`](../connectors/mercury-connector/)
(`src/rules.rs`; conditions `min_usd`, `max_usd`, `methods`, `payee`), proved
live by `tests/mercury_rules_e2e.sh` (MR0–MR7).

**`status` reports it.** The connector's `status` (or whatever operation
reports the policy) answers `confirm` with the other members, as the policy
holds it: `["send"]`, `[]`, or `null` when the policy has none. The member is
present as `null` rather than absent because a reader — the dashboard's policy
editor, a test that must put a policy back as it found it — has to tell "this
policy asks for nothing" from "this build does not know the member". An
absent member reads as the second. Gmail reports the policy by serialising the
struct, so every member, `confirm` included, is there under its own name; its
test `status_reports_every_member_of_the_policy` destructures the struct with
no `..`, so a member added later does not compile until it is reported.

Where a policy is sealed on chain (Gmail seals it to `reply_pubkey`), `confirm`
is sealed with the rest: it is part of the policy.

## 3. The flow in code

### Preparing: the write operation

The write operation does everything it does before it acts — reads the
policy, builds the action from the call, checks it against the policy and the
limits — and only then asks whether the owner wants to see it. From
`connectors/gmail-connector/src/main.rs`:

```rust
fn send(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    let message = Prepared::from_call(input, &rules)?;
    // Before anything is built, sent, or shown to the owner.
    message.check(&rules)?;
    if rules.confirms(policy::Confirmable::Send) {
        return confirm::ask(&message);
    }
    let sent = deliver(&rules, &message, policy::Counted::Own)?;
    Ok(sent_as_answered(&sent, on_chain()))
}
```

`ask` builds three things and opens the task
(`connectors/gmail-connector/src/confirm.rs`):

* **The display** — what the owner is shown. Every value the action will use,
  each as a field, and nothing the action uses that is not shown. `WrittenBy`
  says whose words a value is: `Agent` for what the call supplied (a body, a
  recipient), `Project` for what the connector computed (an amount, a limit
  price, a fee).
* **The state** — the exact action, serialised, sealed beside the task and
  handed back to `confirm`. It is the only thing `confirm` acts on.
* **The policy** — the policy's bytes as stored (`policy::stored()`), the same
  bytes `confirm` will pass. A policy that changed in between makes the task
  `void`.

```rust
pub(crate) fn ask(message: &Prepared) -> Result<Value, String> {
    let message = shown(message);          // line ends as the owner reads them
    check_shown(&message)?;                // shown whole, or refused
    let state = serde_json::to_vec(&without_attachments(&message))
        .map_err(|e| format!("the message could not be kept: {e}"))?;
    let mut task = tasks::confirm(display(&message)?, "confirm", &state, &policy::stored());
    for attachment in &message.attachments {
        let (name, content_type, data) = as_file(attachment)?;
        task = task.file(&name, &content_type, &data);
    }
    let opened = task.open().map_err(|e| e.refusal())?;
    Ok(tasks::awaiting_owner(&opened))
}
```

What cannot be shown whole is refused, never shown in part: Gmail refuses a
body over 50000 characters with `display_invalid` before it opens anything.
Bulk the owner must see but a field cannot hold goes in as the task's files
(Gmail's attachments), not in the state: the state holds 256 KiB, the files
6 MiB together, and the owner can open a file.

A task whose action depends on a price takes a short life:
`tasks::confirm(…).life_seconds(n)`.

`tasks::awaiting_owner(&opened)` is the whole answer to the agent:
`status: "awaiting_owner"`, `task_id`, `task_hash`, `thread`, `expires_at`,
`link`. It names the task with its hash, which the owner's page checks against
the run's attestation ([TASKS.md, The proof](TASKS.md#the-proof)), so it goes
into the answer unchanged.

### Answering: `confirm`

The platform calls `confirm` in a run of the agent that prepared the task, on
the owner's approval, with `task_id`, `task_hash`, the owner's `approval`
(`{at, public_key, signature, nonce}`), and what the owner wrote sealed to
the task's reply key: `supplied` for an `input` task, `note` beside any
approval. The operation:

1. Checks what it can without the task: the call names a task and a hash, the
   policy is there and readable. A refusal here leaves the task as it was —
   the platform records it, and the task ends `failed` with
   `run_refused:unreported` (a refusal of the connector's own, which the host never saw) or `run_refused:<reason>` (one of the host's) when the run ends without taking the answer.
2. Takes the answer — `tasks::answered_for("confirm", &input, &policy)` for a
   connector that reads its input as JSON, which reads the id, the hash, the
   approval, `supplied` and `note` off the input; or `tasks::answered(id,
   hash, "confirm", &policy, &approval, None, note)` for one with an input
   struct. The host holds the run to the consent sealed in the task — the
   preparer's key, wallet, identity and compute limit — then verifies the
   owner's signature over the task, the hash and the sealed words, and only
   then moves the task. On `Ok` the task is `answering` and never returns to
   `open`; the state, the files, `supplied` and `note` come back in the
   `Answer`, opened.
3. Reads the action from `answer.state` into the same type it was sealed from
   (`deny_unknown_fields`: a state with a member this build does not know is
   not an action).
4. Checks it again against the policy and the limits as they are now, and
   counts it in this run's own cell, beside the agent's direct actions (§4c).
5. Carries out exactly that action.
6. Reports the result to the preparer with `tasks::report` — the owner's
   note goes into it — and answers the run.

```rust
pub(crate) fn confirm(input: &Input) -> Result<Value, String> {
    let (call, rules) = before_answer(input, policy::load())?;
    let answer = tasks::answered_for(ANSWERED_BY, &call, &policy::stored()).map_err(|e| e.refusal())?;
    after_answer(&rules, &answer, crate::on_chain(), crate::deliver, |id, result| {
        tasks::report(id, result).map_err(|e| e.refusal())
    })
}

fn after_answer(
    rules: &policy::Policy,
    answer: &tasks::Answer,
    on_chain: bool,
    send: impl FnOnce(&policy::Policy, &Prepared, policy::Counted) -> Result<Value, String>,
    report: impl FnOnce(&str, &[u8]) -> Result<(), String>,
) -> Result<Value, String> {
    let message = held(&answer.state, &answer.files).map_err(closed)?;
    message.check(rules).map_err(closed)?;
    let mut sent = send(rules, &message, policy::Counted::Confirmed).map_err(closed)?;
    if let Some(note) = answer.note.as_deref().and_then(|n| std::str::from_utf8(n).ok()) {
        sent["note"] = serde_json::json!(note);
    }
    report(&answer.id, sent.to_string().as_bytes()).map_err(|e| sent_unreported(e, &sent))?;
    Ok(answered_with(&sent, &answer.id, on_chain))
}
```

`after_answer` takes the action and the report as arguments so that a unit
test drives everything after the answer without a host (§7).

A task answered and not reported ends `failed`; the report is what makes it
`done`. What is reported is sealed for the preparer, so it may be whole —
Gmail reports the recipients and the subject with the message id.

### The operations the SDK serves

`task_status`, `task_cancel`, `task_delete`, `tasks` and `tasks_unlock` are
the same in every project:

```rust
if let Some(answer) = tasks::dispatch(operation, &input) {
    return answer;
}
```

Gmail, whose input is a struct, rebuilds the one member they read:

```rust
pub(crate) fn task(operation: &str, input: &Input) -> Result<Value, String> {
    let call = serde_json::json!({ "task_id": input.task_id });
    tasks::dispatch(operation, &call)
        .unwrap_or_else(|| Err(format!("unknown operation `{operation}`")))
}
```

A refusal of the interface is `TaskError`; `e.refusal()` is `code: sentence`
with the codes of [TASKS.md, The host interface](TASKS.md#the-host-interface),
so a connector answers it as it answers its own refusals.

### Turns

A task may ask the owner for text or a file instead of a yes:
`tasks::input(display, "supply", Supplies::Text, &state, &policy)`. A task
opened by the run that answered another continues that task's `thread`: the
answering operation of `connectors/tasks-probe` opens the next task of the
conversation from inside `supply`, and a game over several turns is one
thread in the owner's inbox. The run that answers is the agent's, so a turn
is the agent's too, opened over HTTPS with the agent's key.

### Telling the owner: notices

When there is nothing to ask — the action is done, or it is the owner's to
know of but not to decide — a connector opens a notice and answers
`notified`:

```rust
let opened = tasks::notice(display, &policy).open().map_err(|e| e.refusal())?;
return Ok(tasks::notified(&opened));
```

A notice names no operation, takes no answer (`answered` on it is
`answer-invalid`) and carries no consent, so it needs no payment key. It is
shown, sealed and limited as a task is, and the owner closes it with Got it.
It is not a receipt: an agent learns what an action did from the outcome of
the task that acted, not from whether a notice was seen. A turn may be a
notice: `connectors/connector-probe` ends the guessing game with one in the
game's thread. A connector that notifies keeps the rules below that concern
what is shown; the rules about acting concern the tasks that are answered.

## 4. Rules

**(a) The action is carried out exactly as it was shown.** `confirm` acts on
`answer.state` and on nothing else: it takes no amount, recipient, price or
flag from its own call, and it does not re-quote, re-resolve or re-read
anything the action was built from. The owner said yes to what they read; an
action rebuilt at confirm time is one they never read. The call of `confirm`
carries `task_id` and `task_hash` and nothing that changes the action.

**(b) An order is shown and executed with its limit price.** A market order
is converted when it is prepared to a limit order at the worst price the
connector's slippage bound allows, and that limit is a field of the task
(`FieldKind::Money`, `WrittenBy::Project`) and part of the state. `confirm`
places it as a limit order at that price. If the market has moved past it,
the order does not fill, or is refused by the venue, and the owner is told
so; it is never placed at a price the owner was not shown. Such a task takes
a short `life_seconds`.

**(c) Limits and budgets are checked twice and counted once.**

| When | Checked | Counted |
|---|---|---|
| prepare | every limit the preparing run can read — the policy's rules, per-action caps, what the call asks for | nothing |
| confirm | every limit again, as it is at that moment — authoritative | at confirm, in the agent's own cell, as a confirmed action |

The check at prepare is an early refusal: the owner is never shown what the
policy forbids, and no task is made for it. The check at confirm is the one
that counts, because time passed and other actions ran. The policy itself
cannot differ (a changed policy voids the task); what differs is counts,
balances, and the venue's own answer.

Both runs that act are the agent's — the direct action, and the `confirm`
the platform starts on the owner's approval — and a run writes its own cell
and no other, so both counts are in the agent's cell, and the owner's cap
bounds each. Gmail's keys are `gm:sends:<day>` and
`gm:sends:<day>:confirmed`:

```rust
pub enum Counted {
    /// A message the caller sends itself: one count a day.
    Own,
    /// A message the owner confirmed, sent by the run started for it: one
    /// count a day, beside the caller's own.
    Confirmed,
}
```

The count is taken as a reservation before the action leaves and released on
any return that did not act (Gmail's `policy::reserve`).

**(d) The owner can read `state_hash`.** The envelope carries the SHA-256 of
the state, and the owner's page holds the envelope. A state drawn from a small
set — a secret number from 1 to 100, a side and a size — is recovered by
hashing every candidate. Anything the owner must not learn from the state goes
in beside a random salt:

```rust
let mut salt = [0u8; 16];
getrandom::getrandom(&mut salt).map_err(|e| format!("no randomness for the task ({e}); nothing was done"))?;
let state = serde_json::to_vec(&json!({ "salt": hex::encode(salt), "secret": number }))
    .map_err(|e| format!("the task could not be kept: {e}"))?;
```

A state whose content is on the task anyway (Gmail's message) needs no salt.

**(e) An answer on chain names nobody.** The run the platform starts for an
approval is an HTTPS call, whose answer may be whole. A connector still
answers by where it runs, as every operation does: on chain, the members of
a fixed list, picked by name, and nothing that names a person, an address, a
subject or an amount the owner would not publish — the output of a run on
chain stays in its transaction for ever. Gmail answers `status`, `task_id`,
`message_id`, `thread_id`, `attachments`, `sent_today`, `remaining_today`:

```rust
const ON_CHAIN: [&str; 5] = ["message_id", "thread_id", "attachments", "sent_today", "remaining_today"];

pub(crate) fn sent_as_answered(sent: &Value, on_chain: bool) -> Value {
    match on_chain {
        true => Value::Object(
            ON_CHAIN.iter().map(|name| (name.to_string(), sent.get(*name).cloned().unwrap_or(Value::Null))).collect(),
        ),
        false => sent.clone(),
    }
}
```

A member added to what the action answers stays off the chain until it is
listed. Where the run lands is `OUTLAYER_EXECUTION_TYPE`: anything but
`HTTPS` is treated as on chain. The same care goes into a refusal: it names
no recipient and no address either. Every connector's `confirm` answer is
built this way; the full result goes to the preparer through `report`, which
is sealed.

**(f) A refusal after the answer says the task is closed, and whether the
action happened.** Once the answer is taken the task is closed whatever
follows. A refusal from then on keeps its own code and adds what is true of
the task. Gmail's words:

| Refused | The task | The refusal |
|---|---|---|
| before the answer: no `task_id` or `task_hash`, no policy, anything the host refuses (`task_not_found`, `not_the_preparer`, `task_approval_invalid`, `task_hash_mismatch`, `task_answer_invalid`, `task_closed`, `task_expired`, `task_void`, `task_store_unavailable`) | as it was in the run; the platform ends it `failed` with `run_refused:unreported` (a refusal of the connector's own, which the host never saw) or `run_refused:<reason>` (one of the host's) when the run ends without taking the answer | as it is |
| after the answer, before the action: a state that does not read, a limit, the credential, the venue's refusal | `failed` | `<code>: <sentence>. The task is closed: to send this message, prepare it again` |
| after the action: the result could not be reported | `failed` | `<code>: <sentence>. The message WAS sent (Gmail message <id>) and the task is closed without its result: do not prepare it again` |

The last row matters most where money moves: an owner who reads "failed"
and prepares the action again would pay twice. The sentence names what
happened and the venue's id for it.

**(g) Only the run the platform started answers, and the host enforces it.**
`answered` refuses `not-the-preparer` in any run that is not the preparer's
on the preparer's key, wallet, identity and compute limit as sealed in the
task — an owner's call, another agent's, the preparer's own call with a
larger limit — and `approval-invalid` without the owner's signature over
this task, this hash and the sealed words, by a full-access key of the
owner's account, within the window; `relayed` in a run a contract made; an
operation other than the one the task names (`answer-invalid`), a hash that
is not the task's, a policy that changed, another build. A connector does
not re-implement any of it and does not compare accounts or verify
signatures itself: it calls `answered` and answers the refusal.

## 5. Prices

A task is paid for when it is prepared. The preparing operation keeps its
price, paid by the agent when the task is made, whether or not the owner
says yes. `confirm` and the five task operations are free: the action was
paid for by whoever asked for it. The run of `confirm` the platform starts on
an approval is admitted only when `confirm` is priced zero — a priced
`confirm` fails every task `operation_priced` — and its compute is paid by
the agent's payment key, as any call of the agent's, within the compute
limit of the run that prepared the task. From
`connectors/gmail-connector/set-prices.sh`:

```json
{"operation": "status",       "price_usd": "0",     "developer_share_bp": 0},
{"operation": "send",         "price_usd": "10000", "developer_share_bp": 0},
{"operation": "confirm",      "price_usd": "0",     "developer_share_bp": 0},
{"operation": "task_status",  "price_usd": "0",     "developer_share_bp": 0},
{"operation": "task_cancel",  "price_usd": "0",     "developer_share_bp": 0},
{"operation": "task_delete",  "price_usd": "0",     "developer_share_bp": 0},
{"operation": "tasks",        "price_usd": "0",     "developer_share_bp": 0},
{"operation": "tasks_unlock", "price_usd": "0",     "developer_share_bp": 0}
```

Every one is priced: an unpriced operation is refused, not free. The script
checks that the priced operations are exactly the manifest's.

## 6. Manifest and build

**Manifest** (`connectors/gmail-connector/manifest.json`):

* `"tasks": true`. A `callers` block beside it must leave the HTTPS door
  open — the run that answers is an HTTPS call of the agent's — and the
  direct door: the owner opens tasks for a new device with a direct call.
* `operations` lists `confirm` and `task_status`, `task_cancel`,
  `task_delete`, `tasks`, `tasks_unlock` beside the connector's own, and so
  does the code's `OPERATIONS` list and its dispatch.
* `describe.operations` has an entry for each: `confirm` (`class: write`,
  params `task_id`, `task_hash`, `approval` and `note`, a doc that says the
  platform runs it on the owner's approval, that it carries out the prepared
  action, what it answers on chain, and that a refusal after the answer
  closes the task); `task_status` and `tasks` (`read`); `task_cancel`,
  `task_delete`, `tasks_unlock` (`write`). The preparing operation's doc says
  it answers `awaiting_owner` when the policy lists it under `confirm`.
* A `limits` entry on the preparing operation has its counterpart on
  `confirm`: Gmail declares 500 a day on both.

**Cargo**:

```toml
outlayer = { version = "0.2", path = "../../sdk/outlayer", features = ["tasks"] }
```

(`features = ["encryption-keys", "tasks"]` in Gmail, which also seals records.)

**`build.sh`** carries three checks, as `connectors/tasks-probe/build.sh`
does:

* the SDK's copy of the interface is the worker's, before anything is built:

  ```bash
  if ! diff -q ../../worker/wit/deps/tasks.wit ../../sdk/outlayer/wit/deps/tasks.wit >/dev/null; then
      echo "ERROR: sdk/outlayer/wit/deps/tasks.wit has drifted from worker/wit/deps/tasks.wit"
      exit 1
  fi
  ```

* the built component imports `outlayer:tasks` (`wasm-tools component wit`);
* the manifest says `"tasks": true`, and its operations and `describe` entries
  agree with the code's dispatch, the SDK's five included.

## 7. Tests a connector ships

**Unit tests** (`cargo test`, no host). The pure parts are tested directly;
everything after the answer is driven through `after_answer` with a stand-in
action and report. Gmail's, by name:

| What | Gmail's test |
|---|---|
| the policy parses `confirm` with the operation's name; `{}`, `[]`, `null` confirm nothing; a read operation, another case, a string instead of a list do not parse | `a_policy_asks_for_the_owner_by_naming_the_operation` |
| `status` reports `confirm` as held, `null` when absent, and every member of the policy | `status_reports_confirm_as_the_policy_holds_it`, `status_reports_every_member_of_the_policy` |
| the state reads back whole, and one with an unknown member does not read | `what_is_kept_is_the_message_and_reads_back_whole` |
| what cannot be shown whole is refused | `a_body_is_shown_whole_or_the_message_is_refused` |
| a refusal before the answer leaves the task as it was | `before_the_answer_a_refusal_leaves_the_task_as_it_was` |
| every refusal after the answer keeps its code and says the task is closed; nothing acts on a refused state | `after_the_answer_every_refusal_keeps_its_code_and_says_the_task_is_closed` |
| `confirm` acts once, on exactly the sealed action, counted as confirmed in the run's own cell, and reports after acting | `what_is_sent_is_what_the_task_held_and_what_is_reported_is_whole` |
| the owner's note reaches the agent with the result, changes nothing of the action, stays off a chain answer, and is cut before the message's own members when the report would not hold it | `the_note_reaches_the_connector_and_changes_nothing_of_the_action` |
| an action that happened and could not be reported says so | `a_message_that_left_and_was_not_reported_is_said_to_have_left` |
| on chain the answer names nobody; a new member stays off | `on_chain_the_answer_names_no_person_and_no_subject` |
| the confirmed count is a record of its own beside the agent's direct count, each bounded by the cap | `a_confirmed_send_is_counted_beside_the_agents_own_and_each_count_is_bounded`, `each_count_has_a_record_of_its_own` |

That the preparing operation opens a task and does not act needs the host,
and is proved live (GT1).

**Live rows** on testnet, modelled on `tests/gmail_delegation_e2e.sh`, whose
owner's page is played by `tests/lib/tasks_owner.mjs` (it signs in with the
owner's key, reads the inbox on a device of its own, and approves with the
owner's key, as the page does):

| Row | Proves |
|---|---|
| GT1 | with the operation under `confirm`, the agent's call answers `awaiting_owner` with the task's id, hash and link and no result of the action; the task waits in the owner's inbox under that hash, addressed to the owner, prepared by the agent, showing the action's values; `task_status` says `open`; the agent's counter did not move |
| GT2 | the owner's approval of the task, signed, starts the agent's run of `confirm`, which acts once; `task_status` says `done` with the result and the run; approving again is refused `task_closed`, and nothing acts twice |
| GT3 | with no `confirm` in the policy the operation acts at once: the answer is the action's and not a task's, and neither the inbox nor `tasks` gains one |
| GT4 | a task with files: the owner's page opens each to the same bytes, and `confirm` acts with them |
| GT5 | the prices on chain: `confirm` and the five task operations cost 0, the preparing operation its price; SKIP when the project has no price rows |

The suite restores the owner's policy on exit and deletes the tasks it made.
Suites run through a keyed RPC (`tests/lib/rpc.sh`).

## 8. Checklist

1. The policy has `confirm: Option<Vec<Confirmable>>`, `Confirmable` a serde
   enum with one variant per write operation of the connector's own, and
   `confirms()`.
2. `status` reports `confirm` with the other members; `null` when absent.
3. Each confirmable operation checks everything it can, then, if
   `confirms(op)`, opens a task and answers `tasks::awaiting_owner(&opened)`.
4. The display shows every value the action uses; what cannot be shown whole
   is refused. The state is the exact action; the policy is the stored bytes.
5. An order is sealed and shown with its limit price; a market order becomes a
   limit at the slippage bound; its task has a short life.
6. A state the owner must not recover from its hash carries a random salt.
7. `confirm` takes the answer with the owner's approval, reads the action
   from the state, re-checks limits, counts the action as confirmed in the
   run's own cell, carries out exactly the action, reports with the owner's
   note, answers.
8. Refusals after the answer say the task is closed, and say so when the
   action happened.
9. On chain, `confirm` answers a fixed list of members that names nobody.
10. `tasks::dispatch` serves the five task operations.
11. Manifest: `"tasks": true`, the HTTPS and the direct door open, `confirm`
    and the five in `operations` and `describe`, a `confirm` limit beside the
    preparing one's.
12. Cargo: the SDK's `tasks` feature. `build.sh`: the WIT copy check, the
    import check, the manifest check.
13. `set-prices.sh`: the preparing operation keeps its price; `confirm` and
    the five are `0`.
14. Unit tests as in §7; live rows GT1–GT5 on testnet.
15. The connector's README says which operations can be confirmed, what the
    owner is shown, what `confirm` answers on chain, and what a refusal does
    to the task.
