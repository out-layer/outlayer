# OutLayer CLI

Command-line tool for deploying, running, and managing OutLayer agents.

```bash
outlayer login                                              # Import NEAR full access key
outlayer create my-agent                                    # Create project from template
outlayer upload my_agent.wasm                               # Publish the built .wasm to FastFS
outlayer deploy my-agent <FastFS URL>                       # Deploy it to OutLayer
outlayer run alice.near/my-agent '{"command": "hello"}'     # Execute agent
```

## Install

```bash
# Prebuilt binary (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/out-layer/outlayer-cli/main/install.sh | sh

# From crates.io (requires Rust 1.86+)
cargo install outlayer-cli

# From GitHub source
cargo install --git https://github.com/out-layer/outlayer-cli

# Update an installed binary to the latest GitHub release
outlayer update
```

Prebuilt binaries for macOS (ARM/x86), Linux (x86/ARM) and Windows (x86) are on the
[Releases](https://github.com/out-layer/outlayer-cli/releases) page. `install.sh`
installs to `/usr/local/bin` (override with `INSTALL_DIR`).

## Quick Start

```bash
# 1. Login (prompts for Account ID and Private Key)
outlayer login              # mainnet
outlayer login testnet      # testnet

# 2. Create a new agent
outlayer create my-agent                     # basic template (stdin/stdout)
outlayer create my-agent --template contract # with OutLayer SDK (VRF, storage, RPC)
cd my-agent

# 3. Edit src/main.rs, build, publish the .wasm and deploy it
./build.sh                                   # writes out/my_agent.wasm (Cargo name: '-' becomes '_')
outlayer upload out/my_agent.wasm
outlayer deploy my-agent <FastFS URL printed by upload>

# 4. Create a payment key for HTTPS calls, and fund it
outlayer keys create
outlayer keys topup 1 --usd 1

# 5. Run your agent (HTTPS when PAYMENT_KEY is set, otherwise on-chain)
export PAYMENT_KEY=$(outlayer keys show 1)
outlayer run alice.near/my-agent '{"command": "hello"}'
```

OutLayer runs published `.wasm` builds: build locally, `outlayer upload`, `outlayer deploy`.
The CLI does not deploy from a GitHub repository.

## Authentication

### Login

```bash
outlayer login                        # mainnet (default)
outlayer login testnet                # testnet
outlayer login --wallet-key wk_...    # custody wallet API key instead of a NEAR key
```

`outlayer login` prompts for an Account ID and an ed25519 private key (`ed25519:...`)
and writes both to `~/.outlayer/{network}/credentials.json`. The private key is kept
in that file in plain text.

`--wallet-key` logs in as a custody wallet: the account and public key come from the
wallet, the `wk_` key is stored in `credentials.json`, and contract calls are signed
through the wallet API. `vault` commands refuse a wallet-key login.

```bash
outlayer whoami             # Account, network, contract, public key, auth type
outlayer logout             # Delete stored credentials for the active network
outlayer about              # Banner and version
```

### Network

Each command picks its network in this order:

1. `OUTLAYER_NETWORK` (`mainnet` or `testnet`)
2. `network` in `./outlayer.toml`
3. `~/.outlayer/default-network`, written by `login`
4. the only network that has a `credentials.json`
5. `mainnet`

`login` takes its network from its argument. `logout`, `whoami` and `create` skip step 2.

| Network | Contract | API |
|---------|----------|-----|
| mainnet | `outlayer.near` | `https://api.outlayer.ai` |
| testnet | `outlayer.testnet` | `https://testnet-api.outlayer.ai` |

## Commands

### Project Workflow

| Command | Description |
|---------|-------------|
| `outlayer create <name>` | Create project from template (basic) in `./<name>/` |
| `outlayer create <name> --template contract` | Create with OutLayer SDK (VRF, storage, RPC) |
| `outlayer create <name> --dir /path` | Create in `/path/<name>/` |
| `outlayer deploy <name> <wasm-url>` | Deploy a published .wasm (the FastFS URL `outlayer upload` prints, or any https URL): creates the project, or adds a version and activates it |
| `outlayer deploy <name> <wasm-url> --no-activate` | Add a version without activating it (a new project's first version is always active) |
| `outlayer deploy <name> <wasm-url> --hash <sha256>` | Skip downloading the file to compute its hash |
| `outlayer run <project> [input]` | Execute agent (HTTPS or on-chain) |
| `outlayer projects [account]` | List projects for an account (default: logged-in account) |
| `outlayer status` | Active version of the project in `./outlayer.toml` |
| `outlayer status <call_id>` | Poll an HTTPS call (uses `PAYMENT_KEY`) |

`deploy` attaches 0.1 NEAR for storage; the contract refunds what it does not use.

A version is a published `.wasm`, named by its sha256, so what a caller runs and
pays for cannot change under that version afterwards — a repository can change
under the same name and commit history can be rewritten. `deploy` computes the
hash from the URL (or takes `--hash`); the worker refuses a file whose bytes do
not match it. For a reproducible build — the same pinned Docker image, the same
hash every time — use `scripts/build_github_wasm.sh --dir ./my-project --target
wasm32-wasip2` from the [OutLayer repository](https://github.com/out-layer/outlayer).

### Run

```bash
# Uses HTTPS when a payment key is found, else on-chain NEAR
outlayer run alice.near/my-agent '{"command": "hello"}'
outlayer run alice.near/my-agent --input request.json             # input from file
echo '{"command": "hello"}' | outlayer run alice.near/my-agent    # input from stdin
outlayer run alice.near/my-agent '{"command": "heavy"}' --async   # async (HTTPS only)
outlayer run alice.near/my-agent '{}' --version <sha256>          # specific version

# Attach secrets (both flags together)
outlayer run alice.near/my-agent '{}' --secrets-profile default --secrets-account alice.near

# Run a published WASM URL directly (always on-chain)
outlayer run --wasm https://main.fastfs.io/alice.near/outlayer.near/<sha256>.wasm '{"cmd": "hi"}'
outlayer run --wasm https://example.com/file.wasm --hash <sha256> '{}'
```

With no input, `run` reads stdin when it is piped, else sends `{}`.

**HTTPS mode** — a project run when a payment key is found: the `PAYMENT_KEY`
environment variable, else a `PAYMENT_KEY=` line in `./.env`. Keys made by
`keys create` are not picked up on their own; `outlayer keys show <nonce>` prints one.

```
POST https://api.outlayer.ai/call/{owner}/{project}
X-Payment-Key: owner:nonce:secret
X-Compute-Limit: <--compute-limit>          (if given)
X-Attached-Deposit: <--deposit>             (if given)
Content-Type: application/json

{"input": ..., "async": false, "version_key": ..., "secrets_ref": {...}}
```

Both headers are amounts in the stablecoin's minimal units (6 decimals: `1000000` = $1).
`--compute-limit` is the call's compute budget and `--deposit` a payment to the project
owner, for example `--deposit 10000` for $0.01. The value is sent as given; the API reads
only a whole number, so a decimal such as `0.01` attaches nothing.

**On-chain mode** — every `--wasm` run, and a project run with no payment key: calls
`request_execution` on the contract with the estimated cost as the NEAR deposit, 128 MB of
memory and 10 seconds. `--compute-limit` is the instruction limit (default 1,000,000,000).
`--async` is refused; `--deposit` is not used.

### Secrets

Encrypted client-side, decrypted only inside the TEE.

| Command | Description |
|---------|-------------|
| `outlayer secrets set '{"KEY":"val"}'` | Encrypt and store secrets (JSON, overwrites) |
| `outlayer secrets update '{"KEY":"val"}'` | Merge with existing (preserves PROTECTED_*) |
| `outlayer secrets set --generate PROTECTED_X:hex32` | Generate protected secret in TEE |
| `outlayer secrets access --access <cond>` | Change who may read a stored secret; the value stays |
| `outlayer secrets list` | List stored secrets (metadata only) |
| `outlayer secrets delete` | Delete secrets for a profile |
| `outlayer secrets set-for-agent '{"KEY":"val"}' --project <owner>/<name>` | Leave a secret for a custody agent to use with one connector |
| `outlayer secrets delete-for-agent --project <owner>/<name>` | Remove it and take the storage deposit back |

```bash
# Set secrets (JSON object, overwrites existing)
outlayer secrets set '{"API_KEY":"sk-...","DB_URL":"postgres://..."}'
outlayer secrets set '{"API_KEY":"sk-..."}' --project alice.near/my-agent
outlayer secrets set '{"API_KEY":"sk-..."}' --wasm-hash <sha256>   # the row a raw WASM URL run reads under
outlayer secrets set '{"SIGNING_KEY":"..."}' --project alice.near/oracle --build <sha256>   # locked to one build
outlayer secrets access --project alice.near/oracle --access whitelist:alice.near --build <new sha256>   # move to the next release

# Named profile (default: "default")
outlayer secrets set '{"KEY":"val"}' --profile production

# Bind to a per-customer vault
outlayer secrets set '{"KEY":"val"}' --vault-id vault.alice.near

# Generate protected secrets in TEE (values never visible)
outlayer secrets set --generate PROTECTED_MASTER_KEY:hex32
outlayer secrets set '{"API_KEY":"sk-..."}' --generate PROTECTED_DB:hex64   # mixed

# Access control
outlayer secrets set '{"KEY":"val"}' --access allow-all                      # everyone who names it
outlayer secrets set '{"KEY":"val"}' --access whitelist:alice.near,bob.near
outlayer secrets set '{"KEY":"val"}' --access whitelist:alice.near,agent.near@2026-12-01T00:00:00Z   # a grant that lapses
# Without --access: a row that exists keeps its condition; a new project row admits only you;
# a new hash row admits everyone.

# Direct calls only: the account that calls the contract must be a reader the condition names
outlayer secrets set '{"SIGNING_KEY":"..."}' --project alice.near/oracle --direct
outlayer secrets access --project alice.near/oracle --direct --via dao.sputnik-dao.near   # and through this contract
outlayer secrets access --project alice.near/oracle --drop-callers                        # remove the rule

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

A deadline in a whitelist entry (`account@...`) is UTC, `YYYY-MM-DDTHH:MM:SSZ` or
`YYYY-MM-DD`; after it the entry no longer admits.

A row is bound to a project (`--project`) or to a build (`--wasm-hash`). A row
bound to a repository is listed by `secrets list` and can be deleted
(`secrets delete --repo <repo> --branch <branch>`); nothing new is stored,
updated or re-scoped for a repository.

`--build <sha256>` locks a project's row to one build: the
condition becomes `And[<access>, WasmHash(hash)]` (or the `WasmHash` leaf alone
under `allow-all`), and the keystore admits only a run whose bytes hash to it.
A rebuild is refused with the build named. The value stays; `secrets access
--build <new sha256>` moves the row to the next release without re-storing, so
a generated `PROTECTED_` key keeps its value — and with no `--access` it keeps
the readers the row already has. `--wasm-hash` is different: it is the accessor
a raw WASM URL run reads under, not a lock on a project row.

On a locked row, `--access …` (in `set` or `access`) is refused: an explicit
condition replaces the stored one, lock included. Pass `--build` to keep it
locked, or `--drop-build` to remove the lock deliberately. The hash is
**Executed binary** in an execution's details on the dashboard. A row that carries
a calling-account rule (`--direct` / `--via`) is protected the same way: replacing
its condition needs `--direct`, `--via` or `--drop-callers`.

`set-for-agent` stores a secret for a **custody agent** to use with somebody else's
connector. It takes the agent's wallet key (`--api-key wk_...` or `OUTLAYER_WALLET_KEY`),
seals the value to the agent's key and stores it under the agent's account. Scope it with
`--project <owner>/<name>` or `--wasm-hash <sha256>`. The logged-in account pays the
storage deposit unless `--agent-pays` is given (the agent's wallet then needs ~0.11 NEAR);
`--vault-id` refuses unless the secret lands under that vault.

### Payment Keys

Payment keys pay for HTTPS API calls.

| Command | Description |
|---------|-------------|
| `outlayer keys create` | Create a new payment key (attaches 0.1 NEAR for storage) |
| `outlayer keys create --project <owner>/<name>` | Let the key pay only for that project; `owner/*` for all of one owner's projects; repeatable |
| `outlayer keys show <nonce>` | Print a key this machine created |
| `outlayer keys list` | List keys with balances |
| `outlayer keys balance <nonce>` | Balance, spent, reserved, initial |
| `outlayer keys topup <nonce> --usd <amount>` | Top up with the stablecoin (any network) |
| `outlayer keys delete <nonce>` | Delete key: the storage deposit is refunded, the remaining balance is forfeited |
| `outlayer keys trial-key [--api-key wk_...]` | Print a custody wallet's nonce-0 key (trial or sponsored); it is derived, so it is read again rather than stored |
| `outlayer redeem <spn_...> [--api-key wk_...] [--payment-key owner:0:key]` | Redeem a sponsor code: a subscription on the wallet's nonce-0 key, paid by the sponsor; stdout is the key. `--payment-key` sends a nonce-0 key issued at random, which cannot be read again, as the proof that binds it; the answer is the derived key that replaces it |

```bash
outlayer keys create
# Payment key created (nonce: 1)
# It pays for any project.
# alice.near:1:a1b2c3d4e5f6...              <- stdout
# Saved to ~/.outlayer/mainnet/payment-keys.json (owner-only). Read it back with: outlayer keys show 1
# Add a balance before using it: outlayer keys topup 1 --usd 1

outlayer keys topup 1 --usd 5
outlayer keys list
outlayer keys balance 1
outlayer keys delete 2
```

A key exists in plain text only on the machine that created it:
`keys create` writes it to `~/.outlayer/{network}/payment-keys.json` (mode 0600)
before sending the transaction, and the chain holds it encrypted for the keystore
only. A key that is not in that file cannot be recovered.

A top-up shows in the balance once the worker has processed it, not instantly.

A deleted key's unspent balance is not refunded and does not move to another
key. Deleting it does not free its nonce: the contract refuses a new key there,
and `keys create` takes the next nonce from the contract
(`get_next_payment_key_nonce`).

### Payment Checks (agent-to-agent)

Token transfers between custody wallets through ephemeral NEAR Intents accounts —
mainnet only. Every `checks` command takes the wallet key (`--api-key wk_...` or
`OUTLAYER_WALLET_KEY`); amounts are in the token's smallest units.

| Command | Description |
|---------|-------------|
| `outlayer checks create <token> <amount> [--memo <text>] [--expires-in <secs>]` | Create a check; prints its `check_key` to hand over |
| `outlayer checks batch-create --file <path>` | Create checks from a JSON array of `{token, amount, memo?, expires_in?}` |
| `outlayer checks claim <check_key> [--amount <n>]` | Claim a check (full, or partial with `--amount`) |
| `outlayer checks reclaim <check_id> [--amount <n>]` | Take back unclaimed funds (full or partial) |
| `outlayer checks status <check_id>` | Status of one check |
| `outlayer checks list [--status <s>] [--limit <n>]` | List checks (`unclaimed`, `claimed`, `partially_claimed`, `reclaimed`, `expired`; default limit 50) |
| `outlayer checks peek <check_key>` | Balance of a check before claiming it |
| `outlayer checks sign-message <message> <recipient> [--nonce <base64>]` | NEP-413 signature by the wallet, for an external service |

### Vaults

Per-customer sovereign vaults ([VAULTS.md](https://github.com/out-layer/outlayer/blob/main/VAULTS.md)).
Every `vault` command that signs needs a NEAR full-access key login, as the vault's parent account.

| Command | Description |
|---------|-------------|
| `outlayer vault init [--name vault] [--parent <account>] [--exit-window 24h] [--webhook-url <https url>]` | Deploy a vault at `<name>.<parent>`, verify it and register it |
| `outlayer vault resume <account>` | Finish an interrupted `init` |
| `outlayer vault status <account>` | Parent, exit window, recovery, registered TEE keys |
| `outlayer vault verify <account>` | `is_vault_verified` and further checks |
| `outlayer vault initiate-recovery <account>` | Cessation-triggered recovery (requires the DAO's `is_ceased`) |
| `outlayer vault initiate-unilateral-recovery <account>` | Parent-only recovery after the exit window |
| `outlayer vault finalize-recovery <account> <ed25519:pubkey>` | Finish a recovery: the key becomes the vault's only full-access key and the TEE keys are removed |
| `outlayer vault set-exit-window <account> <window>` | Change the exit window for future recoveries |
| `outlayer vault unlocked-add-key <account> <ed25519:pubkey> [--full-access]` | After a recovery, add a key (default: function-call key with 1 NEAR allowance) |

### Upload (FastFS)

Upload files to on-chain storage via NEAR transactions.

| Command | Description |
|---------|-------------|
| `outlayer upload <file>` | Upload file to FastFS |
| `outlayer upload <file> --receiver <account>` | Custom receiver (default: the OutLayer contract, `outlayer.near` / `outlayer.testnet`) |
| `outlayer upload <file> --mime-type <type>` | Override MIME type (default: from the file extension) |

```bash
outlayer upload ./target/wasm32-wasip2/release/my_agent.wasm
#   SHA256: <sha256>
#   ...
# FastFS URL: https://main.fastfs.io/alice.near/outlayer.near/<sha256>.wasm
```

The URL is `https://<host>/<sender>/<receiver>/<sha256>.<ext>`; the host is
`main.fastfs.io` on mainnet and `test.fastfs.io` on testnet. Files over 1 MiB are
sent in 1 MiB chunks, one transaction each. A wallet-key login uploads through the
wallet API.

> **Note:** FastFS upload transactions **fail on purpose** with "Exceeded the prepaid gas": gas is set to 1, because no contract code needs to run — the FastFS indexer reads the file from the transaction arguments regardless of execution status. The file is served at its FastFS URL once the indexer has picked it up; a chunked file, once every chunk is indexed.

### Versions

Read the project from `./outlayer.toml`.

| Command | Description |
|---------|-------------|
| `outlayer versions` | List project versions (up to 50; keys shortened to 10 characters) |
| `outlayer versions activate <key>` | Switch active version (`<key>` is the full sha256) |
| `outlayer versions remove <key>` | Remove a version |

### Earnings

| Command | Description |
|---------|-------------|
| `outlayer earnings` | View blockchain + HTTPS earnings |
| `outlayer earnings withdraw` | Withdraw blockchain earnings to the logged-in account |
| `outlayer earnings history` | View earnings history (default: 20 entries) |
| `outlayer earnings history --source blockchain` | Filter by source: `blockchain` or `https` |
| `outlayer earnings history --limit 50` | Custom limit |

### Logs

| Command | Description |
|---------|-------------|
| `outlayer logs` | Execution history of the key `payment_key_nonce` in `outlayer.toml` names |
| `outlayer logs --nonce 2` | History for a specific key |
| `outlayer logs --limit 50` | Custom number of entries (default: 20) |

## Configuration

### Files

| Path | Contents |
|------|----------|
| `~/.outlayer/{network}/credentials.json` | Account, public key, and the private key or `wk_` key |
| `~/.outlayer/{network}/payment-keys.json` | Payment keys this machine created (mode 0600) |
| `~/.outlayer/default-network` | Network chosen by the last `login` |

### Project Config

`outlayer.toml` in your project root (created by `outlayer create`). The fields the CLI reads:

```toml
network = "mainnet"        # network for commands run in this directory

[project]
name = "my-agent"          # status, versions, and the default secrets accessor
owner = "alice.near"

[run]
payment_key_nonce = 1      # outlayer logs; add it yourself
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OUTLAYER_HOME` | Config directory (default: `~/.outlayer`) |
| `OUTLAYER_NETWORK` | Network: `mainnet` or `testnet` |
| `OUTLAYER_RPC_URL` | NEAR RPC endpoint for the active network (default: `https://rpc.mainnet.near.org` / `https://test.rpc.fastnear.com`) |
| `PAYMENT_KEY` | Payment key for `outlayer run` and `outlayer status <call_id>` (format: `owner:nonce:secret`); also read from a `PAYMENT_KEY=` line in `./.env` |
| `OUTLAYER_WALLET_KEY` | Custody wallet API key (`wk_...`) for `checks`, `redeem`, `keys trial-key`, `secrets set-for-agent` / `delete-for-agent` |

### Global Flags

```bash
outlayer --verbose ...            # also -v; available on all commands
```

## Templates

### basic (default)

Rust + wasm32-wasip2 project: reads JSON from stdin, writes JSON to stdout.

### contract

Rust + wasm32-wasip2 with the `outlayer` SDK crate (VRF, storage, NEAR RPC bindings).

Both include `Cargo.toml`, `src/main.rs`, `build.sh`, `.gitignore`, `skill.md` and
`outlayer.toml`. `build.sh` builds for `wasm32-wasip2` and copies the result to
`out/<name>.wasm`, with `-` in the name replaced by `_`.
