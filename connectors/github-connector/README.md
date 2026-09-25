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
  "marker": "\n\n— posted by an AI agent via OutLayer"
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

`status` is free, a read costs $0.001, a write $0.01.

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

There is no operation that forwards a request of the agent's choosing. The
platform prices by operation and the policy allows by action; a passthrough
would be one price and one permission for everything.

Answers are cut down to what an agent uses. GitHub describes one pull request in
15 KB, most of it URLs of other endpoints.

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
./build.sh                    # checks the manifest against the code; prints the SHA256

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
| `src/policy.rs` | the owner's rules, the globs, and the day's counter |
| `src/github.rs` | the REST client and GitHub's refusals turned into what to do |
| `src/seal.rs` | sealing the policy to a caller's `reply_pubkey`, for answers that land on chain |

## Tests

`cargo test` covers the policy (globs, fail-closed, the four refusals nothing
else makes, paths that try to climb out), the translation of GitHub's answers,
the day's counter with its give-back, and the seal against the golden vector the
dashboard's test opens.
