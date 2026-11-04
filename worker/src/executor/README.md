# Executor Module

Runs a guest wasm with resource limits, on wasmtime, for WASI Preview 1
modules and Preview 2 components.

## Files

```
executor/
├── mod.rs           - Executor, format dispatch, run limits
├── wasi_p1.rs       - WASI P1 executor (wasm32-wasip1 / wasm32-wasi)
├── wasi_p2.rs       - WASI P2 executor (wasm32-wasip2) and host-interface linking
├── sandbox.rs       - what a run gets of the host: preopens, store limits, epoch ticker
└── pinned_http.rs   - guest HTTP connected to the address the SSRF filter checked
```

## Formats

### WASI Preview 2 (P2)
- **Target**: `wasm32-wasip2`, component model, entry `wasi:cli/run`
- **Host**: `wasi:http` and the OutLayer host interfaces in `worker/wit/`
  (RPC, storage, payment, VRF, wallet, signing keys, encryption keys, tasks)
- **Files**: no directory is preopened while `sandbox::GUEST_FILES_ALLOWED` is
  false; every file call answers an error
- **Network**: no raw sockets (TCP, UDP and name lookup denied); outbound HTTP
  only through `wasi:http`, the outbound allowlist and the egress audit

### WASI Preview 1 (P1)
- **Target**: `wasm32-wasip1`, `wasm32-wasi`, core module, entry `_start`
  (`fn main()`)
- **Host**: stdin, stdout, stderr, environment, clock, random; no host
  interfaces, no network, no declared keys

Both: JSON input on stdin, output from stdout (capacity `MAX_OUTPUT_BYTES`;
a write past it fails), secrets as environment variables, fuel metering for
instructions, the epoch ticker for the time limit, and linear memory between
`WASM_MEMORY_FLOOR_MB` and `WASM_MEMORY_CEILING_MB`.

## Dispatch

`Executor::execute` → `execute_async`:

1. A module that declares signing or encryption keys runs only with exactly
   those keys (`check_run_keys`); otherwise it is refused before
   instantiation.
2. With a known `build_target`, the matching executor runs and its error is
   returned as is: `wasm32-wasip2` → `wasi_p2::execute`,
   `wasm32-wasip1` / `wasm32-wasi` → `wasi_p1::execute`.
3. With none, P2 is tried, then P1; a binary that is neither fails.

## Adding a target

1. A module `src/executor/<name>.rs` with an `execute` that takes the bytes,
   input, `ResourceLimits`, env vars and returns output and instructions used,
   like `wasi_p1::execute`.
2. A match arm in `execute_async()` and a step in the fallback order.
3. The compiler side ([compiler README](../compiler/README.md)).
4. Tests in `worker/tests/` with a fixture in `wasi-examples/`.

## Testing

```bash
cargo test --lib executor
```

Integration tests and the fixtures they need: [worker/TESTING.md](../../TESTING.md).

## Common errors

| Error | Cause |
|---|---|
| `Not a valid WASI Preview 2 component` | Not a component: build with `wasm32-wasip2` |
| `Failed to find _start function` | A `[lib]` crate: build a binary (`fn main`) |
| `Failed to instantiate component` | The component imports an interface version or shape the worker does not serve ([wit/README.md](../../wit/README.md)) |

## See also

- [WASI Tutorial](../../../wasi-examples/WASI_TUTORIAL.md)
- [Worker README](../../README.md)
