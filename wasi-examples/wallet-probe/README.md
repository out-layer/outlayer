# wallet-probe

A WASI module whose only job is exercising the `outlayer:wallet` host
functions (`worker/wit/deps/wallet.wit`, implemented in
`worker/src/outlayer_wallet/host_functions.rs`) from a real guest.

## Why it is not part of `connector-probe`

The worker gives a component the wallet host functions only if the component
**imports** them (`has_wallet_import` in `worker/src/executor/wasi_p2.rs`). On a
run that names no wallet every one of them answers:

```
no_wallet: this run has no wallet; the operation needs a call made with the wallet's own payment key and X-Wallet-Id
```

so the import is harmless to a module that never calls them. Here every
operation calls them, and `connector-probe` keeps the wallet out so that its
own answers stay about the connector path and nothing else.

## Not a connector

No `connector_id` in the manifest, so it is an ordinary project: no curated
registry entry, no on-chain price table, no per-operation fee. It needs none of
that — the wallet calls are host functions, so there is no egress to allow and
nothing to price per operation.

The manifest is still embedded, and it says one thing worth saying:

```json
"capabilities": { "network": [] }
```

For an ordinary project an empty list is **enforced** while a missing key is
not, and those are different claims. So a module that can move money here
cannot talk to the internet, and `build.sh` checks the section is in the
artefact rather than trusting that it is.

### Deploy it under a normal account, NOT `connectors.outlayer.*`

Being a connector is a line in `connector_registry.rs` and a coordinator
deploy, so publishing under the connector namespace would not make this one —
`lookup_by_project_id` matches an exact name in that hardcoded list. What it
WOULD do is put it inside other people's spending scope: a trial key is issued
scoped to `{connectors namespace}/*`, and `scope_allows` matches by **owner**,
not by registry membership. A non-connector sitting in that namespace is
therefore payable out of the trial allowance we give away, at compute price,
for a module that exists to be poked at.

Anywhere else is fine — `zavodil.testnet/wallet-probe` and the like. Nothing
about the wallet host functions depends on the owner.

## Calling it

Two things are required and neither is optional:

* `X-Payment-Key: <owner>:<nonce>:<secret>` — a payment key the custody wallet
  itself owns: its owner is the wallet's implicit account. A key owned by a
  named account identifies no wallet, and the call is refused with
  `X-Wallet-Id cannot be honoured for this credential`. A `Bearer wk_...` alone
  does not pay for a call and is refused (`wk_is_not_a_payer`).
* `X-Wallet-Id: <wallet id>` — the wallet must be **named**. An absent header,
  or one with an empty value, means "no wallet": the header is trimmed and
  dropped when blank, and a call that never asked for a wallet does not get
  one. For this module that means every operation answers `no_wallet`.

Get the id from `GET /wallet/v1/address?chain=near` (authenticated with the
wallet's `Authorization: Bearer wk_...`; `wallet_id` in the response), then:

```bash
curl -s -X POST "https://testnet-api.outlayer.ai/call/$OWNER/wallet-probe" \
  -H "X-Payment-Key: $WALLET_PAYMENT_KEY" \
  -H "X-Wallet-Id: $WALLET_ID" \
  -H 'Content-Type: application/json' \
  -d '{"input":{"operation":"whoami"}}'
```

The id you send must be your own. Naming another wallet is refused
(`match_requested_wallet`), which is the point: the header requests the wallet
the credential already identifies, it never selects one.

## Operations

| `operation` | Moves money | What it proves |
|---|---|---|
| `whoami` | no | `wallet::get_id` answers, and its answer matches the `WALLET_ID` the environment was given. Two sources for one fact, and only the host function is authoritative |
| `balance` | no | the derived NEAR address and what it holds — the two reads an agent makes before deciding to spend |
| `transfer` | **yes** | what a refusal looks like from inside a guest: the code, whether retrying is pointless, and which request holds the wallet |
| `request_status` | no | the id out of a `wallet_busy` refusal is one a guest can actually poll |

`transfer` takes `to` and `amount` (yoctoNEAR, decimal string):

```json
{"input":{"operation":"transfer","to":"bob.testnet","amount":"1000000000000000000000"}}
```

A caller-chosen recipient is safe here in a way a caller-chosen HTTP host would
not be: the host function acts as the caller's own wallet under that wallet's
own policy, so the worst it can name is a destination for their own money —
which they can already reach through `POST /wallet/v1/transfer` without this
module.

## Reading the answer

Every `wallet::*` function returns `(result, error)`, and the error carries
everything an agent must decide next. This module does not pass the string
through — it **parses** it and reports the pieces, because an error a program
can route on is a different thing from one a human can read:

```json
{
  "ok": true,
  "operation": "transfer",
  "detail": "refused as `wallet_busy` — the wallet is held by request 9f1c-42. Poll it with …",
  "error": "wallet_busy: a swap is using this wallet … in_flight_request_id=9f1c-42 in_flight_operation=swap",
  "error_parsed": {
    "code": "wallet_busy",
    "message": "a swap is using this wallet …",
    "in_flight_request_id": "9f1c-42",
    "in_flight_operation": "swap"
  }
}
```

Two conventions that matter when reading a run:

* **`ok` is about the ANSWER, not about the outcome.** A well-formed refusal is
  a working interface, so `transfer` reports `ok: true` for it. What sets
  `ok: false` is an answer nothing can be done with: no machine code, or both
  halves of the tuple empty.
* **A missing `terminal` is missing, not `false`.** An agent that reads absence
  as "retryable" hammers a permanent refusal.

## Producing a `wallet_busy` refusal

It cannot be done from inside one run. The host functions block, so a single
guest's calls never overlap — the wallet has to be held by something else.
Start a slower operation on the same wallet first (a swap, a cross-chain
withdraw, or another `/wallet/v1/call`), then call `transfer` here within it.
The refusal arrives after the grace period, which is 2 seconds
(`WALLET_BUSY_GRACE` in the coordinator).

**`in_flight_request_id` can be absent while `in_flight_operation` is not.** The
coordinator withholds the id until the request row is actually written — an id
handed out earlier answers `404`, which reads as a request that was lost. So a
busy answer arriving in that first moment names the operation and no id: wait
briefly and ask again. When the operation records no request row at all (a
cross-chain deposit intent), no id is ever coming, and the message says so.

`in_flight_operation` is worth branching on either way: a `transfer` clears in
seconds, a `cross_chain_withdraw` can run for minutes.

Then feed the `in_flight_request_id` straight back:

```json
{"input":{"operation":"request_status","request_id":"9f1c-42"}}
```

That second call is the half nothing else checks. A busy refusal that names a
request nobody can read is a dead end dressed as an instruction.

## Publishing

```bash
./build.sh          # checks the WIT copy, the manifest section and the wallet import
outlayer upload target/wasm32-wasip2/release/wallet-probe.wasm   # prints the FastFS URL
outlayer deploy wallet-probe <FastFS URL>                        # adds the version and activates it
```

`build.sh` refuses to produce an artefact that does not import
`outlayer:wallet/api`: a build without it would run happily and test nothing.
It also diffs `wit/wallet.wit` against the worker's copy and reports a drift
rather than fixing it — which side is right is a decision, not a build step.
