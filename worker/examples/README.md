# Worker Examples

Standalone development programs; not part of the test suite.

## test_fuel_component.rs

Loads a WASI P2 component (`wasi-examples/ai-example`) into a wasmtime engine
with fuel metering enabled and sets a fuel budget on a store. It checks that a
component loads with `consume_fuel(true)`; it does not run the component.

```bash
cd wasi-examples/ai-example
cargo build --release --target wasm32-wasip2

cd ../../worker
cargo run --example test_fuel_component
```

Output: `✅ Component loaded with fuel enabled!` and `✅ Fuel metering WORKS
with component model!`, or the load / fuel error.

## Adding an example

`examples/<name>.rs` with a `main`, run with `cargo run --example <name>`.

Worker tests: [../TESTING.md](../TESTING.md). Live suites:
[tests/README.md](../../tests/README.md).
