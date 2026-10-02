# connector-probe

A connector that does nothing useful, so that everything **around** a connector
can be tested.

The real connectors need something outside the platform to answer — near.email
is mainnet-only, Mercury needs a bank account — which leaves the connector path
itself unexercisable by them alone: pricing, the fixed fee per firing, the
per-operation caps, the owner's secret, the outbound allowlist. This one is
published like a connector, priced like a connector and metered like a
connector — and reports back what it saw, with nothing external in the way.

**Testnet only.** The registry lists it on testnet and nowhere else
(`ConnectorProbe::networks` in the coordinator), so on mainnet nothing at
`connectors.outlayer.near/connector-probe` is a connector at all. A test
connector reachable in production would be an extra door into a worker that
holds keys, opened for nobody's benefit.

## Publishing

The project id must be **`connectors.outlayer.testnet/connector-probe`**, and
that is the whole difficulty: `outlayer deploy` signs as the one identity the
CLI has stored, so running it here publishes `<you>/connector-probe` — a project
the registry does not recognise as a connector, with no price and no fee. The
version has to be added BY the namespace account, which means near-cli:

```bash
./build.sh                      # checks the manifest section, prints the SHA256
outlayer upload target/wasm32-wasip2/release/connector-probe.wasm
# → https://test.fastfs.io/<uploader>/outlayer.testnet/<hash>.wasm
# Who uploaded only shows up in the URL. The contract records url + hash, and
# the worker verifies the hash, so any fetchable URL serving those bytes works.

near contract call-function as-transaction outlayer.testnet add_version \
  json-args '{"project_name":"connector-probe",
              "source":{"WasmUrl":{"url":"<url>","hash":"<hash>","build_target":"wasm32-wasip2"}},
              "set_active":false}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
  sign-as connectors.outlayer.testnet network-config testnet sign-with-legacy-keychain send

# Check the URL really serves those bytes, then activate. `version_key` IS the hash.
near contract call-function as-transaction outlayer.testnet set_active_version \
  json-args '{"project_name":"connector-probe","version_key":"<hash>"}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as connectors.outlayer.testnet network-config testnet sign-with-legacy-keychain send
```

Adding with `set_active:false` first is the point: nothing any caller runs
changes until the activation, the previous version stays published, and a
rollback is one `set_active_version`. A new OPERATION also needs its price row
(`scripts/set_connector_prices_testnet.sh`, signed by the contract owner), or
the coordinator refuses it with `unknown_operation` however good the wasm is;
that table is cached for up to a minute.

It is called like any other project:

```
POST /call/connectors.outlayer.testnet/connector-probe
```

A different owner is a different project: the registry only recognises the name
under the namespace, so a probe published anywhere else is an ordinary project
with no price and no fee.

## Operations

| `operation` | Price | What it proves |
|---|---|---|
| `ping` | free | a free operation is still a REAL price: it runs only on a key that can pay, and is refused when the key cannot |
| `whoami` | $0.01, share 0 | what the guest was TOLD about its caller — injected by the worker, not taken from the request. Priced with the whole fee staying with the platform, which is the shape of every connector we own ourselves |
| `env` | free | every system variable the worker injects, one row each: whether it arrived, whether it is blank, and what it holds — the whole injected environment as the guest sees it |
| `secret` | $0.01 | the owner's secret reached the guest, without printing it |
| `author_secret` | free | the AUTHOR's secret (`PROBE_AUTHOR_SECRET`, manifest `author_secrets.profile = author`, stored by the publishing account) is in the environment of every run, with no header and no `secrets_ref` |
| `burn` | $0.01 | compute costs something: `{"operation":"burn","rounds":50}` burns instructions on demand |
| `fetch` | $0.015 | the declared host (`rpc.testnet.fastnear.com`) is reachable |
| `forbidden_fetch` | $0.015 | an undeclared host (`example.com`) is NOT |
| `vrf` | $0.01, share 0 | `near:vrf`: randomness with the alpha it is bound to, and the public key beside it. A key that cannot be read is reported, not fatal — the alpha is what the proof rests on. Share 0 because what it proves is not about money |
| `refund` | $0.01, share 70% | `near:payment`: the module hands part of the fee back, and over-refunding is refused — `ok` stays true either way, because a refused refund is still a well-formed answer, and `refund_error` carries the outcome. The share is deliberately NOT zero: a refund comes out of the AUTHOR's earnings, so with no share there would be nothing for the ledger row to show |
| `sockets` | free | raw TCP (`1.1.1.1:80`) and a DNS lookup are refused — `wasi:http` is the only way out |
| `trap` | $0.01 | the module panics: the call fails, the fee is refunded, the author is paid nothing |
| `fail` | $0.01 | the module answers `ok: false` and exits 1 — shows how a non-zero exit is reported and billed |
| `sleep` | $0.01 | sleeps `seconds` (≤ 600) so the execution limit, not the module, ends the run |
| `budget` | free | a daily budget kept the way the connectors keep theirs: `mode` reserve / release / read against `cap` on counter `run`, through the atomic `storage::increment`; `tests/connector_budget_parallel_e2e.sh` fires it in parallel to show the cap holds |
| `guess_start` | $0.01, share 0 | tasks between an agent and its owner, over several turns: picks a number and leaves the owner the first task of a game (below) |
| `guess` | free | the agent's run on the owner's answer to a turn, started by the platform on the owner's approval: judges the guess, reports it, and opens the next turn in the same thread — or, on a right guess, a notice that says so |
| `task_status`, `task_cancel`, `task_delete`, `tasks`, `tasks_unlock` | free | the SDK's own task operations (`outlayer::tasks::dispatch`) |
| `unpriced` | — | absent from the price table AND unimplemented here: must be refused before anything runs |

`forbidden_fetch` **passes when it fails**: `ok: false` with an `http_error` is
the expected result. A success means an undeclared host was reachable from
inside a TEE that holds keys, and the manifest allowlist is not being enforced.

## The guessing game

A conversation of several turns through tasks (`docs/TASKS.md`): the agent
starts a game, the owner plays it from the inbox, and neither of them reads the
number.

**The agent starts it.** The call names the owner's row, which must admit the
agent's account **by name** (a `whitelist:` access, as in the next section);
a row open to everyone is refused `not_granted_by_name`.

```bash
curl -s https://testnet-api.outlayer.ai/call/connectors.outlayer.testnet/connector-probe \
  -H "X-Payment-Key: $AGENT_PAYMENT_KEY" -H 'Content-Type: application/json' \
  -d '{"input": {"operation": "guess_start", "max": 100},
       "secrets_ref": {"account_id": "you.testnet", "profile": "shared"}}'
```

`max` is a whole number from 2 to 1000, and 100 when it is not named. The run
picks a number from 1 to `max` and opens an `input` task, `Guess my number`,
asking `I picked a number from 1 to {max}. Your guess?`; the answer carries
`status: "awaiting_owner"`, `task_id`, `task_hash` and the inbox `link`.

**The owner plays it in the inbox.** The page seals the text they type and
asks their wallet for one signature; the platform starts `guess` as a run of
the agent — on the agent's own payment key — which judges it:

- wrong — reports `higher` or `lower` with the attempt count, and opens the
  next task of the same thread, which shows the guess, the answer and the
  attempts so far;
- not a whole number from 1 to `max` — a wrong turn too: an answered task
  cannot be un-answered, so the next task says `not a number from 1 to {max}`
  and the game goes on;
- right — reports `guessed in {n} attempts`, and leaves the owner a notice in
  the same thread, `You guessed it: {number}, in {n} attempts`, which asks
  nothing: the owner closes it with Got it.

**The agent reads the outcome** with `task_status` (`{"operation":
"task_status", "task_id": "…"}`) or `tasks`. The result of a turn is
`{attempt, guess, verdict, max, detail}`, with `next_task_id` when the game goes
on and `notice_task_id` when it was won (`next_error` or `notice_error` when
that could not be opened). Every turn is the agent's: the run that judges a guess is the agent's, so
the task it opens is the agent's too, and the agent follows the whole game
with `task_status` on each `next_task_id`, or with `tasks`. Each turn costs
the agent one run; the owner pays nothing and sends no transaction.

**Where the number is.** In the task's sealed `state`, handed from turn to
turn — not in storage, so that nothing of the game is kept between runs but
the sealed task itself. The envelope the owner reads carries
`state_hash`, the SHA-256 of the state, so the state carries 32 random bytes
beside `{secret, max, attempts}`: without them, hashing the state of every
number from 1 to `max` would name the secret.

## The secret

The probe reads secrets exactly as any project does, so both routes an agent
has are exercised against it. Keys it looks for: `PROBE_TOKEN`, `PROBE_SECOND`.

**Named in the body.** Any row whose on-chain condition admits the calling
wallet — typically the owner's, stored once under the owner's account with the
agent's wallet account whitelisted:

```
outlayer secrets set '{"PROBE_TOKEN":"…"}' --project connectors.outlayer.testnet/connector-probe \
  --profile shared --access whitelist:you.testnet,<agent account>
```

and the call carries `"secrets_ref": {"account_id": "you.testnet", "profile": "shared"}`.
Revoking is `outlayer secrets access … --access whitelist:you.testnet`. This is
what `wasi-examples/test-secrets-example/tests/03_project_model.sh` C1 drives.

**The agent's own row, by header.** Stored under the AGENT's own account, which
is what the keystore compares against the caller:

```
accessor: Project("connectors.outlayer.testnet/connector-probe")
profile:  <agent account>      # the 64-hex custody wallet account
owner:    <agent account>
```

Use `POST /wallet/v1/agent-secret/prepare` (the author pays, the agent needs no
NEAR) or `POST /wallet/v1/agent-secret` (the agent's own wallet signs), then
call with `X-Use-Owner-Secret: 1` and no `secrets_ref`. With neither the header
nor a body reference, no secret is looked up at all — which is itself worth
testing: `operation: "secret"` should then report `found: false` for everything.
When both are present the body wins.

## What it never does

It never returns a secret's value, and never takes a host to fetch from the
caller. A test tool that could be pointed at an arbitrary host would be an SSRF
gadget with a TEE's network access; one that echoed secrets would turn every
test run into a leak.

## Where the full runbook is

`docs/TESTNET_RUNBOOK.md` in the coordinator repository — the ordered list of
calls that checks each limit and each refusal, with what a pass looks like.
