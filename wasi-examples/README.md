# WASI Examples for NEAR OutLayer

Collection of examples and tools for developing WASM modules for NEAR OutLayer platform.

## 📚 Documentation

### [WASI Tutorial](./WASI_TUTORIAL.md) - **START HERE**
Complete guide for developing WASI modules:
- WASI Preview 1 vs Preview 2
- Quick start templates
- Input/output patterns
- Requirements and best practices
- Common pitfalls and solutions

### [Test Runner](./wasi-test-runner/) - **VALIDATE YOUR MODULE**
Universal tool to test WASM modules for compatibility:
```bash
cd wasi-test-runner
cargo build --release
./target/release/wasi-test --wasm your-app.wasm --input '{"test":"data"}'
```

## 📦 Examples

### [random-example](./random-example/) - WASI P1
Simple random number generator demonstrating:
- ✅ WASI Preview 1 (wasm32-wasip1)
- ✅ Binary format with `main()`
- ✅ JSON input/output via stdin/stdout
- ✅ Random number generation
- ✅ ~111KB binary size

**Use case**: Basic computations, random numbers, simple I/O

### [ai-example](./ai-example/) - WASI P2
HTTP client for AI APIs demonstrating:
- ✅ WASI Preview 2 (wasm32-wasip2)
- ✅ Component model
- ✅ HTTP/HTTPS requests
- ✅ OpenAI-compatible API integration
- ✅ Fuel metering

**Use case**: HTTP requests, API calls, external data fetching

### [oracle-example](./oracle-example/) - WASI P2
On-demand price oracle demonstrating:
- ✅ WASI Preview 2 (wasm32-wasip2)
- ✅ Multiple HTTP sources (CoinGecko, CoinMarketCap, TwelveData)
- ✅ Price aggregation (average, median, weighted)
- ✅ Encrypted API keys via env vars
- ✅ Batch requests (up to 10 tokens)

**Use case**: Decentralized oracles, price feeds, multi-source data aggregation

## 🚀 Quick Start

### 1. Choose Your WASI Version

**WASI P1** - For simple computations:
```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
```

**WASI P2** - For HTTP and advanced I/O:
```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

### 2. Follow the Pattern

```rust
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Input { /* your fields */ }

#[derive(Serialize)]
struct Output { /* your fields */ }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    // Parse JSON
    let data: Input = serde_json::from_str(&input)?;

    // Process...
    let result = process(data)?;

    // Write to stdout
    let output = Output { result };
    print!("{}", serde_json::to_string(&output)?);
    io::stdout().flush()?;

    Ok(())
}
```

### 3. Test Locally

```bash
# With wasmtime
echo '{"test":"data"}' | wasmtime your-app.wasm

# With test runner (recommended)
cd wasi-test-runner
./target/release/wasi-test --wasm ../your-app.wasm --input '{"test":"data"}'
```

### 4. Deploy to NEAR OutLayer

OutLayer runs a published `.wasm`, named by its sha256. Publish the file you
built and register it as a project version:

```bash
outlayer upload your-app.wasm
# prints SHA256 and: FastFS URL: https://test.fastfs.io/your.testnet/outlayer.testnet/<sha256>.wasm
outlayer deploy your-app <FastFS URL> --target wasm32-wasip1
```

Then call it:

```bash
near call outlayer.testnet request_execution '{
  "source": {
    "Project": {"project_id": "your.testnet/your-app", "version_key": null}
  },
  "resource_limits": {
    "max_instructions": 10000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  },
  "input_data": "{\"test\":\"data\"}"
}' --accountId your.testnet --deposit 0.1
```

## ✅ Requirements Checklist

Before deploying to NEAR OutLayer, ensure:

- ✅ Using `[[bin]]` format (not `[lib]`)
- ✅ Have `fn main()` as entry point
- ✅ Reading from stdin (not args)
- ✅ Writing to stdout (not stderr)
- ✅ Flushing stdout after write
- ✅ JSON input/output format
- ✅ Output ≤ 900 bytes
- ✅ Built with wasm32-wasip1 or wasm32-wasip2
- ✅ Tested with [test runner](./wasi-test-runner/)

## 🛠️ Cargo.toml Template

```toml
[package]
name = "your-app"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "your-app"
path = "src/main.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# For WASI P2 only:
# wasi-http-client = "0.2"

[profile.release]
opt-level = "z"  # Optimize for size
lto = true       # Link-time optimization
strip = true     # Strip debug symbols
```

## 🔧 Useful Commands

```bash
# Check binary type
file your-app.wasm

# Check size
ls -lh your-app.wasm

# Test with input file
echo '{"test":"data"}' > input.json
wasmtime your-app.wasm < input.json

# Inspect with wasm-tools
wasm-tools print your-app.wasm | head -50

# For P2 components
wasm-tools component wit your-app.wasm
```

## 📖 Additional Resources

- [NEAR OutLayer Project](../) - Main project documentation
- [wasmtime Book](https://docs.wasmtime.dev/) - Runtime documentation
- [WASI Specification](https://github.com/WebAssembly/WASI) - Official WASI docs
- [Component Model](https://github.com/WebAssembly/component-model) - WASI P2 spec

## 🐛 Troubleshooting

### Common Errors

| Error | Solution |
|-------|----------|
| "entry symbol not defined: _initialize" | Use `[[bin]]` instead of `[lib]` |
| "Failed to find _start function" | Add `fn main()` entry point |
| Empty output | Add `io::stdout().flush()?` |
| "Not a valid WASI P1/P2" | Check build target |
| Output truncated | Reduce output to ≤900 bytes |

See [WASI_TUTORIAL.md](./WASI_TUTORIAL.md#common-pitfalls) for detailed solutions.

## 🎯 Example Use Cases

### WASI P1 Examples
- Random number generation
- Hash computation (SHA256, etc.)
- JSON transformation
- Data validation
- Simple calculations
- Text processing

### WASI P2 Examples
- API requests (REST, GraphQL)
- AI/ML inference calls
- Price oracles
- Data aggregation
- Content fetching
- Multi-step workflows

## 🤝 Contributing

To add your own example:

1. Create new directory in `wasi-examples/`
2. Follow the patterns in existing examples
3. Test with [test runner](./wasi-test-runner/)
4. Add README with usage instructions
5. Update this file with link to your example

## 📝 License

The examples in this directory are dual-licensed under **MIT OR Apache-2.0**, at your
option — see `LICENSE-MIT` and `LICENSE-APACHE` here. This is deliberately more
permissive than the rest of the repository (Apache-2.0), because examples are meant to
be copied into your own product without an attribution burden you might overlook.

Note that most subdirectories here are **git submodules** with their own repositories,
and are governed by the `LICENSE` in those repositories rather than by these files:
`random-example`, `ai-example`, `echo-example`, `oracle-example`, `captcha-example`, `weather-example`,
`private-dao-example`, `botfather-example`, `env-test-example`, `test-secrets-example`,
`vrf-example`, `intents-example`, `eth-proof-example`, `near-email`.

`near-email` is Apache-2.0 rather than dual-licensed: it is a finished product built on
OutLayer, not an example to copy from.

See [LICENSING.md](../LICENSING.md) for the full component map.

---

**Last updated**: 2025-10-15
**Compatible with**: wasmtime 28+, NEAR OutLayer MVP
