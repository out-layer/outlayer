# GitHub connector

An agent works in the owner's GitHub account — **as the owner** — without ever
holding the credential. Issues, comments, files, branches, commits, pull
requests, reviews and gists. The token stays in the enclave; the owner's policy
decides what the agent may do with it.

There are no prompts here and no judgement. This is an interface to GitHub: what
to read, what to write and whether a change is any good is the agent's business;
whether it is ALLOWED is this module's.

## Two fences, and they are different

**GitHub's fence.** The owner installs the OutLayer GitHub App on the
repositories they choose and authorizes it. The token then reaches those
repositories and nothing else — a repository outside the installation answers
404, as if it did not exist. The app is not permitted workflow files, settings
or administration, so those are refused whatever anyone asks.

**The owner's fence**, in `GITHUB_POLICY`, enforced here before a request leaves:
which actions, which repositories, which branches and paths, how many writes a
day. Four refusals have no other guard at all — GitHub would accept every one of
them from this token:

| refused by the policy alone | why it matters |
|---|---|
| a public gist | a public gist is world-readable and indexed, for ever |
| any write under `.github/` | `CODEOWNERS`, issue templates and Dependabot decide who reviews and what runs |
| merging a pull request | it puts the agent's work into a branch nobody re-read |
| approving one | an approval in the owner's name can satisfy a branch protection rule |

Without a policy only `status` runs. Not "read-only": reading a private
repository is a disclosure too.

## The policy

```jsonc
{
  "actions": ["issue_get", "issue_comment", "pr_files", "pr_review"],
  "repos": ["outlayer-ai/*"],        // `owner/name`, `owner/*`, or ["any"]
  "branches": ["agent/*"],           // writable branches; absent: no file writes
  "paths": ["docs/*", "notes/*"],    // writable paths; absent: any but `.github/`
  "max_writes_per_day": 40,          // required for any write
  "allow_merge": false,
  "allow_approve": false,
  "allow_public_gists": false,
  "marker": "\n\n— posted by an AI agent via OutLayer",
  "confirm": ["pr_review"]          // writes that wait for the owner; absent: none
}
```

Every field narrows; absent means the narrowest reading, not the widest. `*`
matches any run of characters, `/` included, and is the only wildcard.

Two rules worth stating on their own:

* **A pattern never reaches the default branch.** `["*"]` allows `agent/x` and
  refuses `main`. An owner who means `main` names it literally.
* **The marker goes on every text the agent posts** — issue bodies, comments,
  review summaries. The agent writes under the owner's name, and this is what
  tells a reader which words were not theirs. Set `"marker": ""` to drop it.

## Operations

`status` is free, a read costs $0.001, a write $0.01. `confirm` and the task
operations are free.

| read | |
|---|---|
| `status` | who the token acts as, which repositories it reaches, the policy, the day's writes |
| `repo_list`, `repo_get` | repositories, filtered by the policy — a name is information too |
| `dir_list`, `file_get` | a directory, or one file up to 256 KB, at any `ref` |
| `branch_list` | branches and their heads |
| `issue_list`, `issue_get` | issues; `issue_get` brings a page of comments with it |
| `pr_list`, `pr_get`, `pr_files` | pull requests, and the patches a review reads |
| `gist_list`, `gist_get` | the owner's gists |

| write | |
|---|---|
| `branch_create` | a branch, from the default branch or from `from` |
| `file_put` | one file, one commit; `sha` to replace an existing one |
| `commit` | several files in one commit, through the Git Data API — up to 50, which is a run's budget and not a policy |
| `issue_create`, `issue_comment`, `issue_update` | open, reply, retitle, label, close |
| `pr_create` | a pull request from a branch the policy allows |
| `pr_review` | `COMMENT`, `REQUEST_CHANGES`, or `APPROVE` when allowed — with comments on lines of the diff |
| `pr_merge` | when `allow_merge` |
| `gist_create`, `gist_update` | secret unless `allow_public_gists` |
| `repo_star`, `repo_unstar` | needs the app's Starring permission |

Every write answers `awaiting_owner` instead when the policy lists it under
`confirm` — see below.

| owner confirmation | |
|---|---|
| `confirm` | run by the platform on the owner's approval, as the agent's own call, with `task_id`, `task_hash`, the owner's `approval` and their sealed `note`: makes the write the task holds |
| `task_status`, `task_cancel`, `task_delete` | a task this caller made, by `task_id`: where it stands, withdraw it, delete it |
| `tasks` | the tasks this caller made for this owner |
| `tasks_unlock` | the owner's own call: opens the waiting tasks for a device that was not signed in when they were made |

There is no operation that forwards a request of the agent's choosing. The
platform prices by operation and the policy allows by action; a passthrough
would be one price and one permission for everything.

Answers are cut down to what an agent uses. GitHub describes one pull request in
15 KB, most of it URLs of other endpoints.

## Asking the owner first

Any write can wait for the owner: `branch_create`, `file_put`, `commit`,
`issue_create`, `issue_comment`, `issue_update`, `pr_create`, `pr_review`,
`pr_merge`, `gist_create`, `gist_update`, `repo_star`, `repo_unstar`. The owner
names the ones they want to see in the policy's `confirm`. A read cannot be
listed, and a name that is not one of these — another case included — makes
the policy unreadable. Absent or `[]`: none, and every write is made at once.

With a write listed, the agent's call is checked as it would be before writing
— the action, the repository, the branch and the default-branch rule, the
paths, `allow_merge`, `allow_approve`, `allow_public_gists`, that
`max_writes_per_day` is set — and instead of writing it leaves a task for the
owner and answers

```json
{"status": "awaiting_owner", "task_id": "…", "task_hash": "…", "thread": "…", "expires_at": 1790000000, "link": "https://app.outlayer.ai/inbox/…"}
```

which is a success: the agent did its part, and paid the write's price. It
learns the outcome from `task_status`. The write waits sealed; the owner
approves it with one message their wallet signs, the platform runs `confirm`
as the agent — on the agent's own payment key, within the compute limit of
the call that prepared the write — and that run makes exactly the write:
nothing in the task says what to do on a yes.

### What the owner is shown

Every value the write will use, and whose words each is — the agent's, or
what the connector read from GitHub:

| write | shown |
|---|---|
| `branch_create` | repository, branch, the branch it starts from, and the commit it starts at, read when the task is made |
| `file_put` | repository, branch, path, commit message, the blob it replaces, the content |
| `commit` | repository, branch, commit message, each changed path with its size — and each content |
| `issue_create` | repository, title, body with its marker, labels, assignees |
| `issue_comment` | repository, number, the comment with its marker |
| `issue_update` | repository, number, and each of state, title, body, labels, assignees it changes — an empty list as "every label is removed" |
| `pr_create` | repository, from and into branch, title, body, draft |
| `pr_review` | repository, number, the pull request's title and head commit, verdict, summary, each line comment with its path, line and side |
| `pr_merge` | repository, number, the pull request's title, its branches, the head commit, the method |
| `gist_create`, `gist_update` | visibility or gist id, description, each file — and each content |
| `repo_star`, `repo_unstar` | repository |

A file's content is shown in a field when it is text a field draws exactly as
written — no carriage return, no character that is invisible or reorders text,
at most 50000 characters — and there is room: a task shows 12 fields, and the
contents shown together hold at most 128 KiB. Any other content is given to the
owner as a file of the task, named `<n>-<name>` after its place in the list,
byte for byte; the list says which is where. A review's line comments that do
not fit a field each are given together as `review-comments.json`. At most 20
changed files, 10 files to open and 6 MiB of them: a write over that is refused
`display_invalid` or `task_too_large` and never shown in part — split it.

Texts are shown and posted with `\n` line ends; a file's content is written as
it was given.

A pull request the owner is asked to merge or review is read when the task is
made, and the owner's yes is bound to the head commit they were shown: the
merge is made with that `sha`, so GitHub refuses it if the pull request moved,
and an approval of any other head is refused `conflict`. A branch is created at
the commit shown. A `commit` is made on the branch's head as it is at
confirmation, and moves the branch without force.

### `confirm`

The platform calls `confirm` in a run of the agent that prepared the task,
with `task_id`, `task_hash`, the owner's `approval` and their sealed `note`.
The host admits it in that run only, and only with the owner's signature over
the task's id, its hash and what they wrote: any other call is refused
`not_the_preparer` or `task_approval_invalid`. The policy the write is judged
by is the one the task was made under — a task made under another is refused
`task_void` — and it is judged again in full, with the default-branch rule
asked of GitHub again. The write is counted as confirmed in the agent's own
cell, then made, and its whole result is left for the agent, sealed, in
`task_status`, the owner's note with it.

| refused | the task | the refusal |
|---|---|---|
| before the answer is taken: no `task_id` or `task_hash`, no policy or an unreadable one, anything the host refuses the answer for (`task_not_found`, `not_the_preparer`, `task_approval_invalid`, `task_hash_mismatch`, `task_answer_invalid`, `task_store_unavailable`, `task_closed`, `task_expired`, `task_void`) | stays as it was in the run; the platform ends it `failed` with `run_refused:unreported` (a refusal of the connector's own, which the host never saw) or `run_refused:<reason>` (one of the host's) | as it is |
| after: a state that is not a write, the policy, the day's count, the token, GitHub's refusal of the write | ends `failed` | its own code, and a sentence ending "The task is closed: to make this write, prepare it again" |
| after the write was made: its result could not be left for the agent | ends `failed` | its own code, and "The write WAS made on GitHub (…) and the task is closed without its result: do not prepare it again" |

**What `confirm` answers.** The run the platform starts is an HTTPS call, so
it answers what the write answers, with `status`, `task_id` and `action`. On
chain (`OUTLAYER_EXECUTION_TYPE` is anything but `HTTPS`) an answer is the
output of a transaction and stays public, so there it carries `status`,
`task_id`, `action`, and of the write's answer
only `number`, `comment_id`, `review_id`, `commit`, `sha`, `created`, `merged`,
`starred`, `state` and `writes_today`: no repository, branch, path, URL or text,
and no gist id — a secret gist's id is its address. A refusal on chain keeps its
code and says what happened in words that name nothing.

**The daily cap counts confirmed writes for the agent that prepared them.** A
run reads and writes the storage cell of the account that made it and no other,
and both runs that write are the agent's — its direct write, and the
`confirm` the platform starts on the owner's approval — so there are two
counts in the agent's cell, and `max_writes_per_day` bounds each:

| count | record | whose cell | written by |
|---|---|---|---|
| the writes an agent makes itself | `gh:writes:<day>` | the agent's | the agent's write |
| the writes the owner confirmed for an agent | `gh:writes:<day>:confirmed` | the agent's | the agent's `confirm`, run on the owner's approval |

The manifest's per-wallet ceiling on `confirm`, 200 a day, stands beside the
ceilings of the writes.

## Refusals

The word before the colon is the contract; branch on it.

| word | what it means | retry? |
|---|---|---|
| `policy_missing`, `policy_unreadable` | the owner has stored no policy, or one this build cannot read | no — the owner acts |
| `policy_denied` | the policy does not allow this | no — the owner acts |
| `invalid` | the request is wrong: a missing field, a bad path, GitHub's own validation | no — fix and call again |
| `not_permitted` | the app is not installed here, or was never given this permission | no — the owner installs |
| `not_found` | no such thing, or a private repository outside the installation | no |
| `forbidden` | the owner's own account may not do this | no |
| `conflict` | the branch or file moved since it was read | read again, then repeat |
| `rate_limited` | GitHub is throttling; the sentence says how long | after the wait, once |
| `token_rejected` | the token was revoked or replaced | no — the owner reconnects |
| `github_unavailable`, `github_unreachable` | GitHub answered 5xx, or could not be reached | later |
| `too_large` | the file is past the limit the operation returns | no |

A refused write costs nothing: the place in the day's budget is taken before
GitHub is called and given back unless GitHub accepted.

## What the owner stores

| key | what it is |
|---|---|
| `GITHUB_TOKEN` | the user token from <https://app.outlayer.ai/connect/github>, or a fine-grained PAT of the owner's own |
| `GITHUB_POLICY` | the JSON above |

Profile `github`, accessor `Project(connectors.outlayer.{testnet,near}/github)`,
access a whitelist of the agents that may use it. There is **no author secret**:
the connector never refreshes the token, so nothing of ours reaches a run.

A token the owner brought themselves works the same way — the connector cannot
tell the two apart, and an owner who would rather not install our app does not
have to.

## Where it is published

| network | project | state |
|---|---|---|
| testnet | `connectors.outlayer.testnet/github` | live |
| mainnet | `connectors.outlayer.near/github` | live |

The active version, its source URL and the prices are on chain and are the only
place to read them from.

## Build, publish, price

```bash
./build.sh                    # checks the manifest against the code and the tasks interface; prints the SHA256

OUTLAYER_NETWORK=testnet outlayer upload target/wasm32-wasip2/release/github-connector.wasm \
  --receiver outlayer.testnet
# first publication:
near contract call-function as-transaction outlayer.testnet create_project \
  json-args '{"name":"github","source":{"WasmUrl":{"url":"<URL>","hash":"<sha256>","build_target":"wasm32-wasip2"}}}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
  sign-as connectors.outlayer.testnet network-config testnet sign-with-legacy-keychain send
# afterwards: add_version with set_active false, check the URL, then set_active_version

CONTRACT=outlayer.testnet OWNER=owner.outlayer.testnet ./set-prices.sh testnet
```

Being a connector also needs an entry in the coordinator's
`connector_registry.rs`, which is code: it arrives with a coordinator release.
Until then the project runs as an ordinary project — no per-operation price, and
no outbound allowlist.

## Layout

| file | what it is |
|---|---|
| `src/main.rs` | the input shape, the dispatch, `status`, and the sealed policy readback |
| `src/ops.rs` | every operation: the policy checks, the call, and what comes back |
| `src/action.rs` | a write as one value: read from the call, checked, resolved, made — what a task holds sealed |
| `src/confirm.rs` | a write the owner confirms: what they are shown, the task, the `confirm` the platform runs on their approval, what it answers on chain |
| `src/policy.rs` | the owner's rules, the globs, and the day's counter |
| `src/github.rs` | the REST client and GitHub's refusals turned into what to do |
| `src/seal.rs` | sealing the policy to a caller's `reply_pubkey`, for answers that land on chain |

## Tests

`cargo test` covers the policy (globs, fail-closed, the four refusals nothing
else makes, paths that try to climb out, `confirm` naming only writes), the
translation of GitHub's answers, the day's counter with its give-back and its
count per preparer, that `status` reports every member of the policy, what each
write shows the owner and keeps sealed, what refuses before and after the
owner's answer is taken, what `confirm` answers on chain and off it, and the
seal against the golden vector the dashboard's test opens.
