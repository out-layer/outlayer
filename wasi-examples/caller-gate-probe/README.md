# caller-gate-probe

A WASI P2 module whose only job is exercising the manifest's `callers` block
(`CONNECTOR_MANIFEST.md`, `callers`). It has one operation, `whoami`, which
answers with what the worker told the run about its caller:

```json
{"build":"v1","execution_type":"NEAR","sender_id":"alice.testnet","user_account_id":"alice.testnet",
 "predecessor_id":"alice.testnet","relayer_id":"","signer_public_key":"ed25519:…"}
```

A run its manifest does not admit never reaches the module: the worker refuses
it before anything executes, and the refusal sentence is the whole answer.

## Builds

`./build.sh` writes nine variants to `target/variants/`, one manifest each
(`manifests/`):

| variant | `callers` | admits |
|---|---|---|
| `open`, `open-v2` | none | every door |
| `direct-only` | `contract: deny`, `https: deny` | direct calls |
| `contract-any` | `direct: deny`, `https: deny` | calls through any contract |
| `contract-relay` | `contract: {only: [relay.outlayer-alice.testnet]}` | that contract calling OutLayer |
| `contract-deputy` | `contract: {only: [deputy.outlayer-alice.testnet]}` | that account calling OutLayer, itself or as a contract |
| `https-only` | `direct: deny`, `contract: deny` | HTTPS calls |
| `meta-tx` | `contract: deny`, `meta_tx: allow` | direct calls, meta-transactions, HTTPS |
| `tasks-direct-deny` | `tasks: true` with `direct: deny` | nothing: the manifest does not parse |

The module imports nothing but WASI. `build.sh` checks that each artefact
carries its own manifest, that the platform's strip keeps it, and that `open`
and `open-v2` hash differently.

## Tests

- `cargo test --test caller_gate_probe` in `worker/`: every build's manifest,
  read out of its bytes, against every door.
- `tests/caller_gate_e2e.sh`: the same builds published as versions of one
  testnet project and called through each door.
