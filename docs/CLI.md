# OutLayer CLI

Command-line tool for deploying, running, and managing OutLayer agents.

```bash
outlayer login                                              # Import NEAR full access key
outlayer create my-agent                                    # Create project from template
outlayer deploy my-agent                                    # Deploy agent to OutLayer
outlayer run alice.near/my-agent '{"command": "hello"}'     # Execute agent
```

## Install

```bash
# From GitHub (requires Rust)
cargo install --git https://github.com/out-layer/outlayer-cli

# From local checkout
cd outlayer-cli && cargo install --path .
```

## Quick Start

```bash
# 1. Login (prompts for Account ID and Private Key)
outlayer login              # mainnet
outlayer login testnet      # testnet

# 2. Create a new agent
outlayer create my-agent                    # basic template (stdin/stdout)
outlayer create my-agent --template contract # with OutLayer SDK (VRF, storage, RPC)
cd my-agent

# 3. Edit src/main.rs, push to GitHub, then deploy
git init && git remote add origin <your-repo-url>
git push
outlayer deploy my-agent

# 4. Create a payment key for HTTPS calls
outlayer keys create

# 5. Run your agent
outlayer run alice.near/my-agent '{"command": "hello"}'
```

## Authentication

### Login

```bash
outlayer login              # mainnet (default)
outlayer login testnet      # testnet
```

Prompts for Account ID and ed25519 private key. Saves credentials to `~/.outlayer/{network}/credentials.json` and OS keychain (macOS Keychain, Linux Secret Service).

```bash
outlayer whoami             # Show current account, network, public key
outlayer logout             # Delete stored credentials
```

The active network is saved to `~/.outlayer/default-network`. If not set, the CLI auto-detects based on which network has credentials.

## Commands

### Project Workflow

| Command | Description |
|---------|-------------|
| `outlayer create <name>` | Create project from template (basic) in `./<name>/` |
| `outlayer create <name> --template contract` | Create with OutLayer SDK (VRF, storage, RPC) |
| `outlayer create <name> --dir /path` | Create in a custom directory |
| `outlayer deploy <name>` | Deploy from current git repo (origin + HEAD) |
| `outlayer deploy <name> <wasm-url>` | Deploy from WASM URL (FastFS, etc.) |
| `outlayer deploy <name> --no-activate` | Deploy without activating |
| `outlayer run <project> [input]` | Execute agent (HTTPS or on-chain fallback) |
| `outlayer projects [account]` | List projects for a user |
| `outlayer status [call_id]` | Project info or poll async call |

### Run

```bash
# Basic execution (uses payment key if available, else on-chain NEAR)
outlayer run alice.near/my-agent '{"command": "hello"}'
outlayer run alice.near/my-agent --input request.json             # input from file
outlayer run alice.near/my-agent '{"command": "heavy"}' --async   # async (HTTPS only)
outlayer run alice.near/my-agent '{"cmd": "premium"}' --deposit 0.01  # attached deposit (USD)
outlayer run alice.near/my-agent '{}' --compute-limit 1000000000  # custom compute limit
outlayer run alice.near/my-agent '{}' --version abc123            # specific version

# Attach secrets to execution
outlayer run alice.near/my-agent '{}' --secrets-profile default --secrets-account alice.near

# Run from GitHub repo (on-chain)
outlayer run --github github.com/user/repo '{"command": "hello"}'
outlayer run --github github.com/user/repo --commit abc123 '{"input": 1}'

# Run from WASM URL (on-chain)
outlayer run --wasm https://alice.near.fastfs.io/outlayer.near/abc.wasm '{"cmd": "hi"}'
outlayer run --wasm https://example.com/file.wasm --hash abc123... '{}'
```

**HTTPS mode** (when payment key is available):
```
POST https://api.outlayer.ai/call/{owner}/{project}
X-Payment-Key: owner:nonce:secret
Content-Type: application/json

{"input": ..., "async": false}
```

**On-chain mode** (fallback): calls `request_execution` on `outlayer.near` contract.

### Secrets

Encrypted client-side, decrypted only inside TEE.

| Command | Description |
|---------|-------------|
| `outlayer secrets set '{"KEY":"val"}'` | Encrypt and store secrets (JSON, overwrites) |
| `outlayer secrets update '{"KEY":"val"}'` | Merge with existing (preserves PROTECTED_*) |
| `outlayer secrets set --generate PROTECTED_X:hex32` | Generate protected secret in TEE |
| `outlayer secrets list` | List stored secrets (metadata only) |
| `outlayer secrets delete` | Delete secrets for a profile |

```bash
# Set secrets (JSON object, overwrites existing)
outlayer secrets set '{"API_KEY":"sk-...","DB_URL":"postgres://..."}'
outlayer secrets set '{"API_KEY":"sk-..."}' --project alice.near/my-agent
outlayer secrets set '{"API_KEY":"sk-..."}' --repo github.com/user/repo --branch main
outlayer secrets set '{"API_KEY":"sk-..."}' --wasm-hash abc123...   # the row a raw WASM URL run reads under
outlayer secrets set '{"SIGNING_KEY":"..."}' --project alice.near/oracle --build <sha256>   # locked to one build
outlayer secrets access --project alice.near/oracle --access whitelist:alice.near --build <new sha256>   # move to the next release

# Named profile
outlayer secrets set '{"KEY":"val"}' --profile production

# Generate protected secrets in TEE (values never visible)
outlayer secrets set --generate PROTECTED_MASTER_KEY:hex32
outlayer secrets set '{"API_KEY":"sk-..."}' --generate PROTECTED_DB:hex64   # mixed

# Access control
outlayer secrets set '{"KEY":"val"}' --access allow-all                      # default
outlayer secrets set '{"KEY":"val"}' --access whitelist:alice.near,bob.near

# Update (merge with existing, preserves all PROTECTED_* variables)
outlayer secrets update '{"NEW_KEY":"val"}' --project alice.near/my-agent
outlayer secrets update --generate PROTECTED_NEW:ed25519

# Generation types: hex16, hex32, hex64, ed25519, ed25519_seed, password, password:N

# List / delete
outlayer secrets list
outlayer secrets delete --project alice.near/my-agent
outlayer secrets delete --profile production
```

Default accessor: `--project` auto-resolved from `outlayer.toml` if present.

`--build <sha256>` locks a project's or repository's row to one build: the
condition becomes `And[<access>, WasmHash(hash)]` (or the `WasmHash` leaf alone
under `allow-all`), and the keystore admits only a run whose bytes hash to it.
A rebuild is refused with the build named. The value stays; `secrets access
--build <new sha256>` moves the row to the next release without re-storing, so
a generated `PROTECTED_` key keeps its value — and with no `--access` it keeps
the readers the row already has. `--wasm-hash` is different: it is the accessor
a raw WASM URL run reads under, not a lock on a project row.

On a locked row, `secrets set --access …` is refused: an explicit condition
replaces the stored one, lock included, and unlocking a row is not what a
command about readers should do silently. Pass `--build` to keep it locked, or
`--drop-build` to remove the lock deliberately. The hash is **Executed binary**
in an execution's details on the dashboard.

### Payment Keys

Payment keys are required for HTTPS API calls.

| Command | Description |
|---------|-------------|
| `outlayer keys create` | Create a new payment key |
| `outlayer keys list` | List keys with balances |
| `outlayer keys balance <nonce>` | Check key balance |
| `outlayer keys topup <nonce> <amount>` | Top up with NEAR (mainnet, auto-swaps to USDC) |
| `outlayer keys delete <nonce>` | Delete key (refunds storage deposit) |

```bash
outlayer keys create
# → Payment key created (nonce: 1)
#   Key: alice.near:1:a1b2c3d4e5f6...
#   Save this key — it cannot be recovered.

outlayer keys list
outlayer keys balance 1
outlayer keys topup 1 0.5       # top up key nonce 1 with 0.5 NEAR
outlayer keys delete 2
```

### Upload (FastFS)

Upload files to on-chain storage via NEAR transactions.

| Command | Description |
|---------|-------------|
| `outlayer upload <file>` | Upload file to FastFS |
| `outlayer upload <file> --receiver <account>` | Custom receiver (default: outlayer.near) |
| `outlayer upload <file> --mime-type <type>` | Override MIME type |

```bash
outlayer upload ./target/wasm32-wasip2/release/my-agent.wasm
# → FastFS URL: https://alice.near.fastfs.io/outlayer.near/abcdef.wasm
```

Files >1MB are automatically chunked.

> **Note:** FastFS upload transactions are **expected to fail** with "Exceeded the prepaid gas" — this is by design. Gas is intentionally set to 1 to minimize costs. No contract execution is needed — the NEAR indexer picks up the file data from the transaction arguments regardless of execution status. The file will be available at its FastFS URL after indexing, which takes 1–2 minutes. Chunked uploads (files >1MB) may take longer since all chunks must be indexed before the file is assembled.

### Versions

| Command | Description |
|---------|-------------|
| `outlayer versions` | List project versions (requires outlayer.toml) |
| `outlayer versions activate <key>` | Switch active version |
| `outlayer versions remove <key>` | Remove a version |

### Earnings

| Command | Description |
|---------|-------------|
| `outlayer earnings` | View blockchain + HTTPS earnings |
| `outlayer earnings withdraw` | Withdraw blockchain earnings |
| `outlayer earnings history` | View earnings history |
| `outlayer earnings history --source blockchain` | Filter by source |
| `outlayer earnings history --limit 50` | Custom limit |

### Logs

| Command | Description |
|---------|-------------|
| `outlayer logs` | View execution history for default payment key |
| `outlayer logs --nonce 2` | History for specific key |
| `outlayer logs --limit 50` | Custom number of entries (default: 20) |

## Configuration

### Credentials

Stored at `~/.outlayer/{network}/credentials.json`. Private key stored in OS keychain when available, fallback to credentials file.

### Project Config

`outlayer.toml` in your project root (created by `outlayer create`):

```toml
[project]
name = "my-agent"
owner = "alice.near"

[build]
target = "wasm32-wasip2"
source = "github"

[run]
payment_key_nonce = 1
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OUTLAYER_HOME` | Config directory (default: `~/.outlayer`) |
| `OUTLAYER_NETWORK` | Network: `mainnet` or `testnet` |
| `PAYMENT_KEY` | Payment key for `outlayer run` (format: `owner:nonce:secret`) |

### Global Flags

```bash
outlayer --verbose ...            # Verbose output (available on all commands)
```

## Templates

### basic (default)

Rust + wasm32-wasip2 project with stdin/stdout I/O.

### contract

Rust + wasm32-wasip2 with OutLayer SDK integration (VRF, storage, NEAR RPC bindings).

Both include: Cargo.toml, src/main.rs, build.sh, .gitignore
