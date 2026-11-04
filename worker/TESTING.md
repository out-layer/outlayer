# Worker Testing

Tests of the worker itself: no coordinator, keystore or chain needed unless a
test says so. Live end-to-end suites against a deployed stack are in
[`tests/`](../tests/README.md).

## Unit tests

```bash
cd worker
cargo test --lib
```

## Integration tests (`tests/*.rs`)

Most run a real wasm through the executor; build the fixture first. A test
whose fixture is missing either panics with the build command or says so and
checks nothing (`wallet_absent`).

| Test | Fixture to build first | Run |
|---|---|---|
| `test_wasm_execution` | `cd ../wasi-examples/random-example && cargo build --release --target wasm32-wasip1` | `cargo test --test test_wasm_execution` |
| `component_tests` | none | `cargo test --test component_tests` |
| `caller_gate_probe` | `../wasi-examples/caller-gate-probe/build.sh` | `cargo test --test caller_gate_probe` |
| `signing_key_probe` | `../wasi-examples/signing-key-probe/build.sh` | `cargo test --test signing_key_probe` |
| `encryption_key_probe` | `../wasi-examples/signing-key-probe/build.sh` | `cargo test --test encryption_key_probe`; the storage cases need `--release` |
| `tasks_probe` | `../connectors/tasks-probe/build.sh` | `cargo test --release --test tasks_probe` |
| `wallet_absent` | `../wasi-examples/wallet-probe/build.sh` | `cargo test --test wallet_absent` |
| `outlayer_rpc_test` | none; reaches NEAR testnet | `TESTNET_NEAR_RPC_URL=<keyed FastNEAR URL> cargo test --test outlayer_rpc_test -- --ignored --nocapture` |

`encryption_key_probe` (storage cases) and `tasks_probe` need a release
build: their store client is reqwest's blocking one, which asserts in a debug
build that it is not inside a tokio runtime — and a wasmtime run always is.

`outlayer_rpc_test` compares the worker's RPC proxy against a direct RPC
call. Give it a keyed RPC URL in `TESTNET_NEAR_RPC_URL` (see the root
`CLAUDE.md`, "Live tests: a keyed RPC, always"); unkeyed, rate limits read as
proxy failures. Never paste the keyed URL into a command that is logged.

## Checking a wasm by hand

```bash
wasm-tools component wit your-app.wasm   # a P2 component's imports and exports
```

[`wasi-examples/wasi-test-runner`](../wasi-examples/wasi-test-runner/README.md)
runs a P1 module or a P2 component locally with an input.

## Execution model the tests assume

- WASI P2 component (`wasm32-wasip2`, entry `wasi:cli/run`) is tried first,
  then WASI P1 module (`wasm32-wasip1` / `wasm32-wasi`, entry `_start`); both
  run on wasmtime with fuel metering.
- Input on stdin, output from stdout (flush it), secrets as environment
  variables.
- No raw sockets; outbound HTTP only through `wasi:http` in a P2 component.
