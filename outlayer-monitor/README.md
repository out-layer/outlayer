# outlayer-monitor

Off-chain race-attack detector and vault-event forwarder for OutLayer per-customer vaults.

A standalone service next to the OutLayer coordinator. It polls FastNEAR's `neardata.xyz` finalized-block feed and reacts to two classes of on-chain events:

1. **MPC receipts** (`request_app_private_key` on the MPC contract, predecessor = the vault) — two calls with the same `(vault_id, derivation_path)` inside the dedup window are the signature of a race attack against the per-vault master. Calls `/admin/ban-vault` + `/admin/evict-customer` on the keystore-worker when auto-ban is on; alerts either way (see [Operating posture](#operating-posture)).
2. **Vault-contract / keystore-DAO logs** — vault-emitted `recovery_initiated_*`, `recovery_finalized_*`, `recovery_window_expired`, `recovery_cancelled_dao_revoked`, `exit_window_set_to_<n>_secs`, `vault_tee_key_added`; DAO-emitted `vault_banned <vault>`, `vault_unbanned <vault>`. Forwarded to the coordinator's `/internal/vault-event` for fan-out to customer webhooks, **after** an independent NEAR RPC cross-check (defense vs a compromised neardata feed). A `recovery_finalized_unilateral` / `recovery_finalized_cessation` log also makes the monitor call `/admin/evict-customer`, so the keystore drops its cached per-vault master (whatever the auto-ban setting).

## Why this exists

Per-vault masters are derived deterministically from `(MPC default_master, predecessor=vault_id, derivation_path)`. The `derivation_path` is `HMAC-SHA256(default_master, "secret-path:vault-master:{vault_id}")` (`keystore-worker/src/mpc_ckd.rs`, `crypto.rs`), which is unguessable by the customer until the worker submits the first request — at that moment the path goes on-chain in plaintext. From then on it's public. The mitigation is **first-write-wins**: any second `request_app_private_key` from the same vault with the same path inside the dedup window is treated as evidence of compromise, and the vault is banned before the attacker can use the derived master.

The vault-event forwarder is independent: it gives customers a Slack/webhook-style stream of state transitions without forcing them to run their own indexer.

## Architecture

```
                         neardata.xyz (FastNEAR)
                                  │
                                  ▼
                          src/source.rs  (lake-source feature)
                                  │
                                  ▼
                          src/run.rs     (per-block dispatch)
                          /             \
              StreamEvent::Mcp     StreamEvent::Vault
                    │                       │
              src/detector.rs           (RPC cross-check)
              (dedup window)                │
                    │                       ▼
                    │             CoordinatorVaultEventForwarder
                    ▼                       │
              KeystoreActionSink  ──▶  POST coordinator
              (ban-vault +              /internal/vault-event
              evict-customer)
                    │
                    ▼
              SlackAlerter | TelegramAlerter | StdoutAlerter
```

## Source layout

| File | Role |
|------|------|
| `src/main.rs`     | CLI parsing, network-default resolution, sink wiring |
| `src/run.rs`      | Per-block iteration loop; dispatches Mcp vs Vault events; eviction on `recovery_finalized_*` |
| `src/source.rs`   | Neardata HTTP adapter; checkpoint persistence |
| `src/detector.rs` | Sliding-window dedup logic; eviction policy |
| `src/sinks.rs`    | `KeystoreActionSink`, alerters (Slack/Telegram/Stdout), `CoordinatorVaultEventForwarder` |
| `src/types.rs`    | Plain-data types (`McpReceipt`, `VaultEventReceipt`, `Verdict`) |

## Build

```bash
# Production: must enable lake-source so the binary actually subscribes
cargo build --release --features lake-source

# Refusing to start without the feature is intentional — it prevents
# silent "no events ever fired" deploys.
```

## Configuration

Every flag can be set through its environment variable (`src/main.rs`). Contract ids and the RPC URL default from `--network`.

| Flag | Env | Notes |
|------|-----|-------|
| `--network` | `OUTLAYER_NETWORK` | `mainnet` or `testnet` (default); selects the neardata subdomain and the defaults below |
| `--mpc-contract` | `OUTLAYER_MONITOR_MPC_CONTRACT` | Default `v1.signer` (mainnet) / `v1.signer-prod.testnet` (testnet) |
| `--keystore-dao` | `OUTLAYER_MONITOR_KEYSTORE_DAO` | Default `dao.outlayer.near` / `dao.outlayer.testnet`; empty string disables vault-event forwarding |
| `--start-block` | `OUTLAYER_MONITOR_START_BLOCK` | **Required.** A recent finalized height on first deploy; an existing checkpoint file wins over it |
| `--checkpoint-path` | `OUTLAYER_MONITOR_CHECKPOINT_PATH` | File for last-block persistence (tmp + rename after every block); unset = replay from `--start-block` on restart. **Set this for production** |
| `--window-blocks` | `OUTLAYER_MONITOR_WINDOW_BLOCKS` | Dedup window. Default 600 (≈10 min) |
| `--keystore-url` | `OUTLAYER_MONITOR_KEYSTORE_URL` | **Required.** One keystore-worker base URL (one of the coordinator's `KEYSTORE_BASE_URLS`) |
| `--worker-token` | `OUTLAYER_MONITOR_WORKER_TOKEN` | **Required.** Worker token (its hash in the keystore's `ALLOWED_WORKER_TOKEN_HASHES`); sent as Bearer to the keystore's `/admin/ban-vault`, `/admin/evict-customer` and to the coordinator's `/internal/vault-event` |
| `--auto-ban-enabled` | `OUTLAYER_MONITOR_AUTO_BAN` | Default `false` (alert-only) |
| `--coordinator-url` | `OUTLAYER_MONITOR_COORDINATOR_URL` | Optional; enables vault-event forwarding when set |
| `--near-rpc-url` | `OUTLAYER_MONITOR_RPC_URL` | RPC for the cross-check. Default `https://rpc.mainnet.fastnear.com` / `https://rpc.testnet.fastnear.com` — the same provider as neardata, so set a different one for real isolation |
| `--slack-webhook-url` | `OUTLAYER_MONITOR_SLACK_WEBHOOK` | Optional alerter |
| `--telegram-bot-token` + `--telegram-chat-id` | `OUTLAYER_MONITOR_TELEGRAM_BOT/CHAT` | Optional alerter |

Alerter priority: Slack > Telegram > stdout JSON. `--telegram-bot-token` without `--telegram-chat-id` refuses to start.

## Operating posture

Default is alert-only (`--auto-ban-enabled` absent / `OUTLAYER_MONITOR_AUTO_BAN=false`):

- The detector still observes and emits structured JSON / Slack / Telegram alerts for every duplicate `(vault_id, derivation_path)` it sees.
- `KeystoreActionSink` does **not** call the keystore — operators read alerts and ban manually if needed.
- Use this mode to confirm the false-positive rate is acceptable on your network and traffic profile.

Once confirmed, pass `--auto-ban-enabled` (or `OUTLAYER_MONITOR_AUTO_BAN=true`):

- Each detected duplicate auto-fires `/admin/ban-vault` + `/admin/evict-customer`.
- Alerts continue to fire so on-call still has visibility.

## Run

```bash
OUTLAYER_MONITOR_START_BLOCK=190000000 \
OUTLAYER_MONITOR_CHECKPOINT_PATH=/var/lib/outlayer-monitor/checkpoint \
OUTLAYER_MONITOR_KEYSTORE_URL=<keystore base URL> \
OUTLAYER_MONITOR_WORKER_TOKEN="$WORKER_TOKEN" \
OUTLAYER_MONITOR_COORDINATOR_URL=https://api.outlayer.ai \
OUTLAYER_MONITOR_SLACK_WEBHOOK="$SLACK_URL" \
OUTLAYER_MONITOR_RPC_URL=<independent RPC> \
./outlayer-monitor --network mainnet
```

Logs go through `tracing` with `RUST_LOG`-style filtering (`outlayer_monitor=info,info` by default).

## Defense-in-depth note

The vault-event forwarder performs an independent NEAR RPC view-call against `--near-rpc-url` BEFORE forwarding any event (the DAO's ban/unban state, the vault's `get_recovery_state` / `get_state` / `get_exit_window` / `get_registered_keys`). This protects customer webhooks from a compromised neardata feed pushing fake `vault_banned` / `recovery_finalized_*` notifications; an event whose view-call does not confirm it, or whose view-call fails, is dropped (not retried). It costs one RPC call per forwarded event. Point `--near-rpc-url` at a different infrastructure provider than the neardata feed for real isolation.
