# Worker Attestation

How NEAR OutLayer ties an execution worker to an approved build running inside Intel TDX,
and what each check does and does not cover.

## Overview

Execution workers run as dstack confidential VMs on Intel TDX hosts operated by OutLayer.
(Compiling a GitHub repository to WebAssembly happens outside the TEE; only execution runs
in the workers.) Attestation happens at three points:

1. **Key registration, on chain, at startup.** The worker's public key is admitted only
   with a TDX quote that Intel's signature chain vouches for and whose five measurements
   (MRTD + RTMR0–3) are on an approved list.
2. **Sessions, off chain.** The worker proves to the coordinator and to the keystore, each
   separately, that it holds a key registered in step 1.
3. **Per-execution attestation.** Every execution produces a fresh TDX quote over a hash of
   the task, which anyone can verify afterwards.

```
Worker (Intel TDX CVM)
  1. keypair in the CVM; TDX quote with the key in report_data
  2. ── register_worker_key ──────────────► worker.outlayer.near (register contract)
                                              verify quote, check 5 measurements,
                                              add the key to its own account
  3. challenge-response ──► coordinator  (session in Postgres)  ─┐ each checks the key
  4. challenge-response ──► keystore     (session in memory)    ─┘ on chain itself
  5. per task: TDX quote over SHA-256(task fields) ──► coordinator ──► public attestation
```

## Stage 1: on-chain key registration

Code: `worker/src/registration.rs`, `worker/src/tdx_attestation.rs`,
`register-contract/src/lib.rs`.

1. **Keypair.** The worker generates a keypair (`WORKER_KEY_TYPE`: `ed25519` by default, or
   `ml-dsa-65`) inside the CVM and writes it to `~/.near-credentials/worker-keypair.json` in
   its container, so a restart that keeps the container reuses the key.
2. **Quote.** It asks dstack (`/var/run/dstack.sock`) for a TDX quote whose
   `report_data[0..32]` is the raw ed25519 public key, or SHA-256 of an ml-dsa-65 public
   key. The quote carries the five measurements of the CVM: firmware, kernel and boot
   configuration, and the application compose (RTMR3).
3. **Pre-check.** It reads the measurements from its own quote and waits for
   `is_measurements_approved` to return `true` before spending gas.
4. **On-chain verification.** The init worker account calls `register_worker_key` on the
   register contract (`worker.outlayer.near`; `worker.outlayer.testnet` on testnet). The
   contract:
   - verifies the quote with `dcap-qvl` against Intel collateral it has cached for the
     quote's platform (FMSPC) — a caller cannot supply its own;
   - refuses any TCB status other than `UpToDate` and any quote with outstanding Intel
     security advisories;
   - requires MRTD + RTMR0–3 together to match one owner-approved entry;
   - requires the submitted key to match the quote's `report_data`;
   - adds the key to its own account as a function-call key: receiver `outlayer.near`,
     methods `resolve_execution`, `submit_execution_output_and_resolve`, `resume_topup`,
     `resume_delete_payment_key`, 10 NEAR allowance.
5. **Result.** `worker.outlayer.near` is the operator account of `outlayer.near`, which
   accepts execution results from it. The worker signs those transactions with the
   registered key.

A worker whose key is already on the account skips the registration call.

| Property | How |
|---|---|
| The key was generated in a TDX CVM | it is bound in the quote's `report_data`, under Intel's signature |
| The CVM runs an approved build | all five measurements must match an entry the contract owner approved |
| The platform is current | TCB `UpToDate`, no advisories, collateral within its validity window |
| The key is scoped | function-call key on four methods of `outlayer.near`, 10 NEAR allowance |

Contract details, collateral handling and the owner's methods:
[register-contract/README.md](register-contract/README.md).

## Stage 2: sessions with the coordinator and the keystore

After registration the worker opens a session with the coordinator and one with the
keystore. Both use the same protocol (`shared-tee-helpers`): the server checks the key on
chain itself, so neither trusts the other.

```
Worker                                   Server
  POST /tee-challenge   (bearer token) ─►  32 random bytes, valid 60 s, one use
  ◄─ {"challenge": "<hex>"}
  POST /register-tee {public_key, challenge, signature}
                                       ─►  1. challenge exists and is fresh
                                           2. signature verifies (allowed key schemes only)
                                           3. view_access_key(OPERATOR_ACCOUNT_ID, public_key)
                                           4. new session
  ◄─ {"session_id": "<uuid>"}
  every later request: Authorization: Bearer <token>, X-TEE-Session: <uuid>
```

| | Coordinator | Keystore |
|---|---|---|
| Endpoints | `POST /workers/tee-challenge`, `POST /workers/register-tee` | `POST /tee-challenge`, `POST /register-tee` |
| Challenge | bound to the worker token that requested it | not bound to a token |
| Session store | Postgres `worker_tee_sessions`, bound to the token; survives restarts | memory; lost on restart |
| Re-registration | deactivates the previous session of the same key | adds a session |
| Enforced when | `REQUIRE_TEE_SESSION=true` | `TEE_MODE=outlayer_tee` |
| Without a session | refused (401) on every worker route except those a compiler outside the TEE also uses (job claim, WASM cache, locks, heartbeat, attestation upload, session setup) | `/decrypt`, `/encrypt`, `/decrypt-raw`, `/storage/*`, `/vrf/generate` refused (403) |

On startup the worker opens both sessions (five attempts each) and stops if either fails.
When the keystore answers "TEE session not found", the worker opens a new session and
retries.

What a session proves and what it does not:

- **Any access key on the operator account passes step 3**, whatever its permission. A
  full-access key on `worker.outlayer.near`, if one is present, opens sessions as a
  TDX-registered key does, and the main contract likewise accepts results from any key on
  that account.
- **The key is checked once**, when the session opens. Sessions do not expire; removing the
  key from the operator account stops new sessions but does not end an open one (a
  keystore session lasts until the keystore restarts, a coordinator session until the same
  key opens a new one or the worker token is deactivated).
- The worker's `user_account_id`, `predecessor_id`, `project_id` and executed WASM hash are
  accepted by the keystore on the trust of the session.

## Stage 3: per-execution attestation

For every execution the worker requests a new TDX quote with

```
report_data[0..32]  = SHA-256( task_type ‖ task_id ‖ repo ‖ commit ‖ build_target ‖ wasm_hash ‖
                               input_hash ‖ output_hash ‖ block_height ‖ caller_account_id ‖
                               project_id ‖ secrets_ref ‖ timestamp ‖ attached_usd )
report_data[32..64] = zero
```

(absent optional fields are skipped; integers are little-endian). The worker uploads it to
the coordinator (`POST /attestations`), and anyone can fetch it:

- `GET https://api.outlayer.ai/attestations/{job_id}`, `/attestations/by-call/{call_id}`,
  `/attestations/by-request/{request_id}`, `/attestations/by-tx/{tx_hash}`
- `GET https://api.outlayer.ai/public/collateral?fmspc=<fmspc>&at=<time>` — the Intel
  collateral that was current when the execution ran

Verifying one means checking the quote's signature chain against that collateral, checking
the five measurements against the register contract's approved list
(`is_measurements_approved`), and recomputing the task hash from the inputs and outputs. The
dashboard's [Trust & Verification](https://app.outlayer.ai/docs/trust-verification) page
and the `outlayer-verify` tool do this.

The per-execution quote binds the result to an approved build, not to the worker's
registered key.

## Threat model

| Threat | Mitigation | Limit |
|---|---|---|
| Unapproved code registers a key | the contract checks the quote and all five measurements | the contract owner decides which measurements are approved |
| Attacker holds a worker token | cannot sign a challenge without a registered key | with enforcement off (`REQUIRE_TEE_SESSION=false`, keystore `TEE_MODE=none`) the token alone is enough |
| Replayed challenge | one use, 60 s lifetime | — |
| Compromised coordinator forges a keystore session | the keystore checks the key on chain itself | the coordinator is trusted for custody in other ways (API keys, policies) |
| Leaked worker key | owner calls `remove_worker_keys`; no new session and no on-chain result with it after that | sessions already open continue, including HTTPS result completion on the coordinator (see Stage 2) |
| Keys of retired workers | `scripts/revoke_old_worker_keys.sh` removes every key not held by a running worker | a key file that survives elsewhere stays valid until removed |
| Full-access key on the operator account | none in the protocol | it passes the operator and session checks; see Governance below |

## Governance at this stage

The register contract's owner (`owner.outlayer.near`) approves measurements, replaces
collateral and removes keys alone, without a vote, and the contract upgrades with the
account's full-access key. Every such action is a public NEAR transaction. See
[docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md#governance-at-this-stage).

## Configuration

### Worker

| Variable | Default | Meaning |
|---|---|---|
| `TEE_MODE` | `none` | `outlayer_tee` in production: real TDX quotes |
| `USE_TEE_REGISTRATION` | `true` | register a TEE-generated key; `false` signs with `OPERATOR_PRIVATE_KEY` instead (development only) |
| `WORKER_KEY_TYPE` | `ed25519` | `ed25519` or `ml-dsa-65` |
| `OPERATOR_ACCOUNT_ID` | — | the register contract account, e.g. `worker.outlayer.near` |
| `INIT_ACCOUNT_ID`, `INIT_ACCOUNT_PRIVATE_KEY` | — | pays for `register_worker_key` (`init-worker.outlayer.near`) |
| `API_AUTH_TOKEN` | — | coordinator worker token |
| `KEYSTORE_BASE_URLS`, `KEYSTORE_AUTH_TOKEN` | — | keystore instances and worker token; required for an execution worker in TEE mode |

### Coordinator

| Variable | Default | Meaning |
|---|---|---|
| `OPERATOR_ACCOUNT_ID` | — | account whose access keys admit a worker session |
| `REQUIRE_TEE_SESSION` | `false` | `true` refuses worker routes without a session |
| `TEE_ALLOWED_KEY_TYPES` | `ed25519` | worker key schemes accepted |

### Keystore

| Variable | Default | Meaning |
|---|---|---|
| `OPERATOR_ACCOUNT_ID` | — | required with `TEE_MODE=outlayer_tee` |
| `TEE_MODE` | `none` | `outlayer_tee` requires a session on worker routes |
| `TEE_ALLOWED_KEY_TYPES` | `ed25519` | worker key schemes accepted |

## Key cleanup

Worker keys stay on `worker.outlayer.near` until removed. After a fleet change:

```bash
./scripts/revoke_old_worker_keys.sh mainnet             # report: keys kept, keys to remove
./scripts/revoke_old_worker_keys.sh mainnet --send      # remove_worker_keys, signed by the owner
```

Each removal frees the key's storage on the account.
