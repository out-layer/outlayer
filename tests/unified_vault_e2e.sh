#!/bin/bash
# NOTE: the shared-helper section below is DUPLICATED in the sibling files — this is now a 3-WAY dup:
#   unified_op_e2e.sh ↔ unified_op_e2e_intents.sh ↔ unified_vault_e2e.sh
# Fixes to ANY helper (env vars, BENEFICIARY, SEED_LOG, the sweep/verify machinery, store_policy, post,
# fund_near, the vault-deploy block, …) MUST be applied to ALL THREE.
#
# Unified VAULT sovereign-exit / recovery / isolation e2e — TESTNET subset (V1,V2,V3,V4,V5) of the
# vault custody surface (per-customer master partitioning + the MPC-CKD sovereign-exit chain).
#
# Where the unified_op_e2e.sh suite exercises the canonical-OP surface (auth-sign / approve-reject /
# sign_message / negatives / delete / on-chain-signer), THIS suite exercises the VAULT surface: the
# isolation guarantees BETWEEN customer scopes, and the irreversible sovereign-exit (`finalize_recovery`)
# that cuts OutLayer off and hands the customer offline re-derivation of every wallet + secret.
#
#   V1  multi-customer vault isolation   — two distinct vault scopes under the SAME parent derive
#                                          DIFFERENT sub-wallet addresses; a client-supplied
#                                          `X-Customer-Vault` header is IGNORED (scope is auth-driven,
#                                          not request-driven)  [ported from vault_multi_customer_isolation.sh]
#   V2  N wallets per ONE vault          — several independent sub-wallets under one vault all derive +
#                                          are usable (distinct wallet_id + address, each reports the
#                                          vault_id); a sub-agent minted under one inherits the vault
#                                          binding  [ported from multi_wallet_vault_e2e.sh]
#   V3  Bearer-near sovereign exit       — derive sub-wallet(s) → finalize_recovery → keystore REFUSES
#                                          to sign afterward → the customer re-derives the SAME address
#                                          OFFLINE (compute-wallet-id → derive-wallet-key) and it matches
#                                          the keystore's reported address. The core sovereignty
#                                          guarantee  [ported from bearer_near_recovery_e2e.sh]
#   V4  detach secret-decrypt BEFORE/AFTER— a secret /call (per-vault-master decrypt) succeeds BEFORE
#                                          recovery and FAILS after finalize_recovery; the on-chain
#                                          ciphertext re-derived locally matches the keystore encryption
#                                          pubkey + decrypts to the expected value  [ported from vault_detach_test.sh]
#   V5  wk_-path sovereign exit          — the /register(`wk_`) analog of V3: finalize_recovery →
#                                          keystore refuses → MPC-CKD master recover → derive-wallet-key
#                                          re-derive → a REAL signed tx lands from the recovered key
#                                          [ported from sovereignty_e2e.sh]
#   V6  a secret CREATED for an agent    — the other end of V4: putting a credential there rather than
#                                          reading one. Both money paths (the agent's own wallet, and a
#                                          BLOCKCHAIN ACCOUNT paying via `store_agent_secret`), the key
#                                          being scope-specific, and what the wallet's signature covers
#                                          — vault, audience, ciphertext, name and payer each altered in
#                                          turn and refused by the contract
#
# ── VAULT-MODE GATE (MPC_PUBLIC_KEY) ─────────────────────────────────────────────
#   V1–V6 are ALL vault-mode tests. Without MPC_PUBLIC_KEY the suite runs in DEFAULT-VAULT
#   mode — it CANNOT `outlayer vault init` a dedicated per-vault, so there is no vault to isolate,
#   recover, retire, or bind a secret to. In that mode V1–V6 are cleanly SKIP-noted (exactly like
#   unified_op_e2e.sh's default-vault handling of its vault-only dimensions) rather than failing. Set
#   MPC_PUBLIC_KEY (bls12381g2:base58 — the same value keystore-worker uses) to deploy real vaults.
#
# ── IRREVERSIBILITY / FUND-LIFECYCLE WARNINGS (read before --apply) ──────────────
#   * `outlayer vault init` LOCKS NEAR (the vault account's storage stake) that the throwaway sub-wallet
#     sweep does NOT reclaim. The sweep machinery copied from unified_op_e2e.sh drains SUB-WALLETS only;
#     the vault stake is a separate vault-lifecycle cost and is NOT auto-returned by this suite.
#   * V3 / V4 / V5 call `finalize_recovery`, which is IRREVERSIBLE — it atomically swaps the vault's
#     FullAccess key (DeleteKey(TEE) + AddFullAccessKey(new_parent)) and flips `unlocked = true`. The
#     vault is MUTATED / RETIRED for OutLayer's purposes the instant V3/V4/V5 run. Each of those tests
#     therefore uses a THROWAWAY vault per run (a fresh `*-$(date +%s)` sub-account). NEVER point them at
#     a vault you still rely on.
#   * Net: after a full --apply run you will have N retired throwaway vaults on chain, each still holding
#     ~0.1 NEAR of locked storage stake. The final summary re-states this.
#   * V6 stakes three 0.1 NEAR storage deposits for the secrets it stores. Only the OWNER — the agent's
#     own wallet — can `delete_secrets` to reclaim one, and it has no gas to, so the suite leaves them.
#
# ── What each test needs ─────────────────────────────────────────────────────────
#   [VAULT]   MPC_PUBLIC_KEY set (so a dedicated vault can be deployed). Everything here is gated on it.
#   [POLICY]  testnet + on-chain policy + Bearer-near auth (signed locally by customer-recovery).
#   [FUNDS]   additionally moves real value (V5's sovereign tx funds + spends a throwaway sub-wallet).
#   Everything is HEADLESS — every signature is produced locally by `scripts/customer-recovery` from
#   keys in ~/.near-credentials (no browser wallet). The exception is the on-chain vault-lifecycle CLI
#   calls (`outlayer vault init / initiate-unilateral-recovery / finalize-recovery`), which the parent
#   signs via its keychain.
#
# ── NOT coordinator-reachable on testnet (documented) ────────────────────────────
#   * V4's secret /call decrypt path requires a pre-deployed WASI project + a production payment key.
#     The reachable subset (pubkey capture → pre-recovery decrypt-success → finalize → post-recovery
#     decrypt-refusal → on-chain ciphertext re-derive == keystore pubkey + local decrypt) is gated on
#     the V4-specific env (SECRET_PROJECT / SECRET_OWNER / SECRET_PROFILE / EXPECTED_SECRET_VALUE /
#     SECRET_PAYMENT_KEY). Absent any of them V4 cleanly SKIP-notes — V3/V5 already prove the
#     keystore-level cutoff via the same per-vault-master code path (wallet sign/derive).
#   * NEAR Intents (regular + confidential) are MAINNET-ONLY — not exercised here (this is a vault
#     surface, not an intents surface); the sweep's intents-withdraw leg is a no-op off mainnet.
#
# Required env:
#   PARENT          vault owner, logged into outlayer-cli [creds in ~/.near-credentials/$NETWORK]
#   MPC_PUBLIC_KEY  bls12381g2:base58 — REQUIRED to run V1–V5 (vault mode). Without it, V1–V5 SKIP.
#   ONLY            optional comma list to run a subset, e.g. ONLY=V1,V3
#   (V4 only)       SECRET_PROJECT=<owner>/<name>  SECRET_OWNER=<acct>  SECRET_PROFILE=<profile>
#                   EXPECTED_SECRET_VALUE=<literal>  SECRET_PAYMENT_KEY=<X-Payment-Key>
#   (V6 only)       CONNECTOR_PROJECT_ID=<owner>/<name> — a project that EXISTS on chain (testnet
#                   defaults to connectors.outlayer.testnet/connector-probe; no mainnet default)
#                   OUTLAYER_BIN=<path> — a CLI with `secrets set-for-agent`, if not on PATH
#
# Run (dry-run prints the plan; --apply executes):
#   MPC_PUBLIC_KEY=bls12381g2:... PARENT=zavodil2.testnet ./tests/unified_vault_e2e.sh --apply

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/agent_secret_mode.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
APPROVER1="${APPROVER1:-zavodil.testnet}"
APPROVER2="${APPROVER2:-}"
EXTERNAL_ACCT="${EXTERNAL_ACCT:-$APPROVER1}"
# Shared constant sink for every DeleteAccount + the sweep's intents-withdraw (real/existing/wNEAR-registered → never burns).
BENEFICIARY="${BENEFICIARY:-$([ "$NETWORK" = mainnet ] && echo zavodil.near || echo zavodil.testnet)}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
WNEAR="${WNEAR:-wrap.testnet}"
# V6 stores a secret against a connector's project, and the contract refuses one
# for a project that does not exist — so this must name a REAL deployed project.
# No mainnet default: naming the wrong one there would store a stranger's secret.
CONNECTOR_PROJECT_ID="${CONNECTOR_PROJECT_ID:-$([ "$NETWORK" = testnet ] && echo connectors.outlayer.testnet/connector-probe || echo "")}"
# V6 drives the real user path (`outlayer secrets set-for-agent`). Override to
# run a build that is not on PATH.
OUTLAYER_BIN="${OUTLAYER_BIN:-outlayer}"
# Every `outlayer` call in this suite targets the network the suite is running
# against. Left unset, the CLI reads ~/.outlayer/default-network — whatever the
# operator last logged into, which on the paying paths decides which chain a
# full access key signs against.
export OUTLAYER_NETWORK="$NETWORK"
# MPC-CKD signer config for vault mode (V1–V5). NOT secret (public key + contract id + domain — per
# user "это не секрет, можно хранить"). TESTNET defaults (this suite is testnet — override all three for
# mainnet). EXPORTED so the `outlayer` CLI (vault init/recovery) AND customer-recovery (--mpc-contract /
# --from-chain) both see them. Unset MPC_PUBLIC_KEY (MPC_PUBLIC_KEY= ./...) → default-vault mode (V1–V5 SKIP).
MPC_PUBLIC_KEY="${MPC_PUBLIC_KEY:-bls12381g2:xeYho48G2Sr9oJz4gw9sLGZGspeeKpHZvMDAwWvoNTRnVMFJH96GxX98TT2MRhTtsot1wcGR1Ti2Xh8PCsbYJ2enbLNdJXDvTYSK8aTE3nJ5NZXU7Kt1F6mFtReWs5pR4kj}"
MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer-prod.testnet}"
MPC_DOMAIN_ID="${MPC_DOMAIN_ID:-2}"
export MPC_PUBLIC_KEY MPC_CONTRACT_ID MPC_DOMAIN_ID
ONLY="${ONLY:-}"
# Per-run tag → V3/V4/V5 deploy FRESH throwaway vaults each run (v3v<RUN_TAG>.$PARENT etc.). The recovery
# tests finalize/dirty their vault irreversibly, so reusing a prior run's vault would fail re-initiate
# ("recovery already in progress" / unlocked). A unique name sidesteps that; abandoned dirty vaults just
# keep their ~0.1 NEAR stake on testnet (not important). V1's vaultb stays a stable reuse (no finalize).
RUN_TAG="$(date +%s)"

# Every throwaway sub-wallet seed is appended here so a leaked wallet can be recovered later
# (deterministic from PARENT_PRIVKEY + seed via `customer-recovery`). SWEEP_QUEUE is the working set
# the EXIT trap sweeps to reclaim funds + on-chain policy storage at the end of the run.
SEED_LOG="${SEED_LOG:-$HOME/.outlayer/uop-seeds.log}"; mkdir -p "$(dirname "$SEED_LOG")"
# These are FILES, not bash arrays: new_subwallet runs in the process-substitution subshell of
# `read -r ... < <(new_subwallet ...)`, where array appends are subshell-local and LOST in the parent
# — a file append (exactly like $SEED_LOG above) survives the subshell. SWEEP_QUEUE is the WORKING set
# the per-test/abort/final sweeps drain (drained + truncated as each batch is swept, so a wallet is
# never swept twice). RUN_LEDGER is the IMMUTABLE full ledger every sub-wallet is appended to and never
# removed from — the final verify_all_drained pass re-checks ALL of them for leaks.
SWEEP_QUEUE="$(mktemp -t uop_sweepq.XXXXXX)"   # pending-sweep working set (drained + truncated each pass)
RUN_LEDGER="$(mktemp -t uop_ledger.XXXXXX)"    # immutable ledger of every sub-wallet this run (for verify)

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); if [[ "$MONEY" == true ]]; then printf '\033[1;31m⛔ HALTING — real-money test %s failed; funds may be mid-flight. The EXIT trap sweeps tracked sub-wallets.\033[0m\n' "$CUR_TEST" >&2; exit 1; fi; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
PASS=0; FAILED=0; FAILED_NAMES=()
# Real-money guard: while MONEY=true (set at the start of each value-moving test, cleared at its end),
# a fail() does not just record — it HALTS the run so funds aren't left mid-flight by a continuing
# suite. The EXIT trap (cleanup_subwallets) still fires and sweeps every tracked sub-wallet.
MONEY=false; CUR_TEST=""

want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# NEAR Intents (regular + confidential) are MAINNET-ONLY — there are no testnet solvers, and the
# coordinator now returns HTTP 503 for the public intents endpoints on testnet. Tests that drive an
# intents-dependent endpoint (deposit/withdraw/swap/cross-chain/payment-check) therefore only run on
# mainnet. Use as: `if want TN && intents_mainnet TN; then ...`. Emits a clean skip note (only when
# `want` already selected the test) and returns non-zero off mainnet so the body is skipped.
intents_mainnet() {
  [[ "$NETWORK" == "mainnet" ]] && return 0
  note "$1 skipped — NEAR Intents are mainnet-only (no testnet solvers; coordinator returns 503 on testnet)"
  return 1
}

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=... MPC_PUBLIC_KEY=... $0 --apply" >&2; exit 1; }
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
for tool in jq curl outlayer near python3; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done

if [[ "$APPLY" != true ]]; then
  warn "Dry-run deploys NOTHING (no vault init → no NEAR locked). Pass --apply to deploy/reuse vaults + exercise the vault isolation + FULL single-run sovereign-exit (finalize + offline re-derive) surface on $NETWORK."
  warn "VAULT suite (V1,V2,V3,V4,V5,V6) — ALL gated on MPC_PUBLIC_KEY (vault mode):"
  warn "       V1 multi-customer vault isolation: two scopes (vault.\$PARENT + vaultb.\$PARENT) → distinct addrs; X-Customer-Vault ignored[VAULT/POLICY]"
  warn "       V2 N wallets per one vault (vault.\$PARENT): distinct wallet_id+addr each; sub-agent inherits binding[VAULT/POLICY]"
  warn "       V3 Bearer-near sovereign exit: derive 3 users → set 60s window → initiate → wait window → finalize_recovery → keystore REFUSES → MPC-CKD master recover → offline re-derive all 3 addrs MATCH[VAULT/POLICY]"
  warn "       V4 detach secret-decrypt: pre-recovery decrypt → set 60s window → initiate → wait → finalize → post-recovery /call REFUSED → on-chain ciphertext re-derive + local decrypt == EXPECTED (gated on SECRET_* env)[VAULT/POLICY]"
  warn "       V5 wk_-path sovereign exit: register wk_ → set 60s window → initiate → wait → finalize → keystore REFUSES → MPC-CKD re-derive same addr → REAL on-chain send-near by recovered key LANDS[VAULT/FUNDS]"
  warn "       V6 a secret CREATED for an agent under the shared vault: key fetched under the agent's own auth + scope-specific → agent-pays store → an unfunded agent refused actionably → \$PARENT pays via store_agent_secret → vault/audience/ciphertext/name/payer each altered and REFUSED, untouched call lands[VAULT/FUNDS]"
  warn "Without MPC_PUBLIC_KEY (default-vault mode) V1–V6 are SKIP-noted (no per-vault to deploy)."
  warn "V6 COST: 0.3 NEAR funding one agent wallet + three 0.1 NEAR storage deposits that only the agent itself could reclaim — the suite does not."
  warn "EXIT WINDOW: the SHARED/V1 vaults deploy with --exit-window 24h (CLI rejects <24h) and are NEVER finalized — they stay reusable. V3/V4/V5"
  warn "       each set a 60s window via a DIRECT set_exit_window contract call (CLI init/set-exit-window reject <24h; the testnet test-timing build allows 60s),"
  warn "       then finalize_recovery in the SAME run after the ~70s window elapses. finalize_recovery is IRREVERSIBLE — V3/V4/V5 use THROWAWAY vaults"
  warn "       (v3v/v4v/v5v.\$PARENT) that are RETIRED (unlocked, OutLayer-side TEE keys deleted) the instant they run; NEVER pointed at vault.\$PARENT."
  warn "       --apply REUSES vault.\$PARENT if already on chain (e.g. vault.zavodil.testnet) — no new stake; a first deploy LOCKS ~0.1 NEAR/vault the sub-wallet sweep does NOT reclaim."
  exit 0
fi

[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-nep413 + sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || { echo "build failed" >&2; exit 1; }

WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || { echo "✗ outlayer logged in as '$WHOAMI', not '$PARENT'" >&2; exit 1; }
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

# Best-effort sweep of every throwaway sub-wallet back to PARENT at exit (self-guards on APPLY;
# defined below, near new_subwallet). Registered here so it covers wallets created by every test.
trap cleanup_subwallets EXIT

near_tty() {
  # Give near-cli-rs a TTY via `script` ONLY when stdout is a real terminal. Headless (CI / a
  # non-TTY harness — where `script` itself errors with "ioctl on socket") falls back to a bare
  # eval: near-cli-rs with full args + sign-with-keychain is fully non-interactive, no TTY needed.
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t uop_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

# account_exists <account_id> → rc 0 iff the account currently exists on chain (view_account returns
# an amount, i.e. no error). Used to REUSE an already-deployed vault (`vault.$PARENT`) instead of
# re-locking stake. A missing account makes view_account return an `error`/`UNKNOWN_ACCOUNT`, which
# yields rc 1 here. Read-only RPC — safe in dry-run too (but only called under --apply).
account_exists() {
  local acct=$1 rpc amount err
  rpc=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$acct\"}}" 2>/dev/null || echo '')
  err=$(echo "$rpc" | jq -r '.error // .result.error // empty' 2>/dev/null)
  amount=$(echo "$rpc" | jq -r '.result.amount // empty' 2>/dev/null)
  [[ -z "$err" && -n "$amount" ]]
}

# ─── shared vault ──────────────────────────────────────────────────────────────
# Default-vault mode (common case): with NO MPC_PUBLIC_KEY we do NOT deploy a
# per-vault — VAULT_ID stays empty, so the bearer tokens omit `--vault-id` (mk_token's
# `${2:+...}`) and the coordinator routes sub-wallets under its DEFAULT vault. Set
# MPC_PUBLIC_KEY to use a dedicated vault instead (the original per-vault path).
#
# DEPLOY IS --apply-GATED. In dry-run (APPLY=false) we deploy NOTHING and leave VAULT_ID="" —
# the same SKIP path the no-MPC_PUBLIC_KEY branch uses (V1–V5 then cleanly SKIP-note). A dry-run
# must never lock NEAR by initializing a real on-chain vault.
#
# REUSE over re-deploy: the dedicated vault is ALWAYS `vault.$PARENT` (the CLI's default --name is
# "vault", so an explicit `--name uop-<ts>` never took — it deployed `vault.<parent>` regardless).
# We therefore RPC view_account for `vault.$PARENT` first; if it already exists we reuse it (run
# `vault resume` idempotently to ensure registration) and skip init entirely — no new stake locked.
# `vault.zavodil.testnet` is already on testnet, so the common testnet run reuses it.
VAULT_ID=""
if [[ -n "${MPC_PUBLIC_KEY:-}" && "$APPLY" == true ]]; then
  CAND="vault.$PARENT"
  log "Resolve shared vault $CAND (reuse if already on-chain, else deploy)"
  if account_exists "$CAND"; then
    VAULT_ID="$CAND"
    note "shared vault $VAULT_ID already on chain — reusing (no new stake); running vault resume idempotently"
    outlayer vault resume "$VAULT_ID" >&2 || warn "vault resume $VAULT_ID failed (already registered?) — continuing"
    pass "shared vault $VAULT_ID reused"
  else
    VAULT_ID="$CAND"
    log "Deploy shared vault $VAULT_ID (--name vault --exit-window 24h)"
    INIT_RC=0
    INIT_OUT=$(outlayer vault init --name vault --exit-window 24h 2>&1) || INIT_RC=$?
    if [[ $INIT_RC -ne 0 ]] && echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
      for _ in 1 2 3 4 5; do sleep 6; if outlayer vault resume "$VAULT_ID" >&2; then INIT_RC=0; break; fi; done
    fi
    [[ $INIT_RC -eq 0 ]] || { echo "✗ vault init failed: $INIT_OUT" >&2; exit 1; }
    pass "shared vault $VAULT_ID deployed"
  fi
elif [[ -n "${MPC_PUBLIC_KEY:-}" ]]; then
  log "Dry-run (no --apply): NOT deploying the shared vault (would lock NEAR). VAULT_ID stays empty → V1–V5 SKIP-note, exactly like default-vault mode."
else
  log "Default-vault mode (no MPC_PUBLIC_KEY): skipping vault init; tokens omit vault-id → coordinator default vault"
fi

mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1" ${2:+--vault-id "$2"}; }
AUTH() { echo "Authorization: Bearer near:$(mk_token "$1" "$VAULT_ID")"; }

# new_subwallet <seed> → echoes "WALLET_ID SUB_ADDR"
new_subwallet() {
  local seed=$1 r wid addr
  r=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$seed")")
  wid=$(echo "$r" | jq -r '.wallet_id'); addr=$(echo "$r" | jq -r '.address')
  # Persist the seed (recoverable from PARENT_PRIVKEY) + track for the EXIT sweep.
  printf '%s %s %s %s\n' "$(date +%s)" "$seed" "$wid" "$addr" >> "$SEED_LOG"
  printf '%s|%s|%s\n' "$seed" "$wid" "$addr" >> "$SWEEP_QUEUE"
  printf '%s|%s|%s\n' "$seed" "$wid" "$addr" >> "$RUN_LEDGER"
  echo "$wid $addr"
}

# ─── fund-return / sweep machinery ────────────────────────────────────────────
# A throwaway sub-wallet can hold value in TWO places: native NEAR on its implicit account AND a
# wNEAR (defuse) balance inside intents.near (T3/T6/T12 deposit wNEAR there). A bare DeleteAccount
# only sweeps the native balance and ORPHANS the intents balance, so every sweep withdraws intents
# FIRST (back to PARENT) and only then deletes the native account. All of this is best-effort: a
# per-wallet error warns and continues, never aborting the suite.
#
# yocto magnitudes (1e22) overflow bash's 64-bit arithmetic, so compare as decimal strings: more
# digits wins; on equal length fall back to lexicographic. Hoisted to file scope so the per-test
# sweep, the EXIT-trap safety net, and the final verify pass all share one comparator/threshold.
SWEEP_MIN="10000000000000000000000"  # 0.01 NEAR in yocto
yocto_gt() { # <a> <b> → "gt" if a > b. RPC amounts/literal here have no leading zeros or sign.
  local a=${1:-0} b=${2:-0}
  if   [[ ${#a} -gt ${#b} ]]; then echo gt
  elif [[ ${#a} -lt ${#b} ]]; then :
  elif [[ "$a" > "$b" ]];      then echo gt
  fi
}

# intents_wnear <addr> → echoes the wallet's wNEAR balance inside intents.near (integer yocto string,
# "0" if none / on any error). intents.near is a multi-token (NEP-245) contract keyed by token_id; we
# read mt_balance_of for "nep141:$WNEAR". Only meaningful on mainnet (no testnet intents), but safe to
# call anywhere — off-mainnet it simply returns "0".
intents_wnear() {
  local addr=$1 args r out
  args=$(jq -nc --arg a "$addr" --arg t "nep141:$WNEAR" '{account_id:$a, token_id:$t}')
  r=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "intents.near" --arg m "mt_balance_of" --arg ab "$(printf '%s' "$args" | base64 | tr -d '\n')" \
        '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$ab}}')" 2>/dev/null || echo '')
  out=$(echo "$r" | jq -r '.result.result // empty | implode' 2>/dev/null | tr -d '"' || echo "0")
  [[ -n "$out" ]] && echo "$out" || echo "0"
}

# sweep_one <seed> <wallet_id> <addr> — drain ONE throwaway sub-wallet back to PARENT, best-effort.
# Order: (1) read native NEAR + intents wNEAR; (2) if both empty → reclaim policy storage only;
# (3) else store an intents_withdraw+delete policy; (4) if intents>0 → withdraw it to PARENT FIRST
# (so it isn't orphaned by the delete); (5) if native>0.01 → DeleteAccount sweeps the rest to PARENT;
# (6) always reclaim the per-wallet policy storage deposit. The intents-before-delete ordering is the
# bug fix: a bare delete would strand the wNEAR sitting in intents.near.
sweep_one() {
  local seed=$1 wid=$2 addr=$3 rpc acct_err native intents wnear_bal
  rpc=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$addr\"}}" 2>/dev/null || echo '')
  acct_err=$(echo "$rpc" | jq -r '.error // .result.error // empty' 2>/dev/null)
  native=$(echo "$rpc" | jq -r '.result.amount // "0"' 2>/dev/null || echo "0")
  # A missing/errored account has no native balance to sweep.
  [[ -n "$acct_err" || -z "$native" ]] && native="0"
  if [[ "$NETWORK" == "mainnet" ]]; then intents=$(intents_wnear "$addr"); else intents="0"; fi
  [[ -n "$intents" ]] || intents="0"

  if [[ "$native" == "0" && "$intents" == "0" ]]; then
    note "sweep: $addr — no native + no intents balance; reclaiming policy storage only"
  else
    # Permissive sweep policy: allow the wNEAR unwrap `call` + the intents withdraw + the native
    # delete. `call` is required for the near_withdraw/storage_unregister unwrap in (4b) below.
    # store_policy is best-effort here — if it fails, the gated call/withdraw/delete below will
    # simply 403 (warned).
    store_policy "$seed" "$wid" '{"rules":{"transaction_types":["call","intents_withdraw","delete"]}}' \
      || warn "sweep: $addr — store sweep-policy failed (call/withdraw/delete may be denied)"
    # (4) intents wNEAR FIRST — withdraw back to PARENT before the account is deleted.
    if [[ "$intents" != "0" && "$(yocto_gt "$intents" "0")" == "gt" ]]; then
      post POST /wallet/v1/intents/withdraw "$seed" "$(jq -nc --arg to "$BENEFICIARY" --arg a "$intents" --arg t "nep141:$WNEAR" '{chain:"near", to:$to, amount:$a, token:$t}')" \
        || warn "sweep: $addr — intents withdraw request errored"
      note "sweep: $addr intents wNEAR ($intents) → $BENEFICIARY (HTTP $HTTP)"
    fi
    # (4b) WRAPPED wNEAR on the wallet's OWN ft balance — a failed intents-deposit leaves the wrapped
    # wNEAR sitting in the wallet's wrap.near ft balance, which a bare DeleteAccount would ORPHAN. Mirror
    # the working manual recovery: near_withdraw (unwrap → native) → storage_unregister (reclaim the
    # registration storage). Both best-effort (a 0-balance / unregistered wallet is a clean no-op).
    # Harmless on testnet (wrap.testnet) — the balance is simply 0 there.
    wnear_bal=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$WNEAR" --arg a "$addr" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"ft_balance_of",args_base64:({account_id:$a}|tojson|@base64)}}')" 2>/dev/null \
      | jq -r '.result.result // empty | implode' 2>/dev/null | tr -d '"' || echo "0")
    [[ -n "$wnear_bal" ]] || wnear_bal="0"
    if [[ "$wnear_bal" != "0" && "$(yocto_gt "$wnear_bal" "0")" == "gt" ]]; then
      note "sweep: $addr holds $wnear_bal wrapped wNEAR (orphaned by a failed intents-deposit) — unwrapping → native before delete"
      post POST /wallet/v1/call "$seed" "$(jq -nc --arg t "$WNEAR" --arg a "$wnear_bal" '{receiver_id:$t, method_name:"near_withdraw", args:{amount:$a}, gas:"50000000000000", deposit:"1"}')" \
        || warn "sweep: $addr — near_withdraw (unwrap wNEAR) request errored"
      note "sweep: $addr near_withdraw $wnear_bal wNEAR → native (HTTP $HTTP)"
      post POST /wallet/v1/call "$seed" "$(jq -nc --arg t "$WNEAR" '{receiver_id:$t, method_name:"storage_unregister", args:{force:true}, gas:"30000000000000", deposit:"1"}')" \
        || warn "sweep: $addr — storage_unregister (reclaim wNEAR registration) request errored"
      note "sweep: $addr storage_unregister on $WNEAR (HTTP $HTTP)"
      # Re-read native so the (5) delete decision below sees the funds the unwrap just added back.
      native=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$addr\"}}" 2>/dev/null \
        | jq -r '.result.amount // "0"' 2>/dev/null || echo "0")
      [[ -n "$native" ]] || native="0"
    fi
    # (5) native NEAR — DeleteAccount sends the FULL remaining balance to BENEFICIARY (only if worth it).
    if [[ "$(yocto_gt "$native" "$SWEEP_MIN")" == "gt" ]]; then
      post POST /wallet/v1/delete "$seed" "$(jq -nc --arg b "$BENEFICIARY" '{beneficiary:$b,chain:"near"}')" \
        || warn "sweep: $addr — delete (native sweep) request errored"
      note "sweep: $addr native ($native yocto) swept to $BENEFICIARY (HTTP $HTTP)"
    elif [[ "$native" != "0" ]]; then
      note "sweep: $addr native $native yocto ≤ 0.01 NEAR — not worth a delete; reclaiming policy only"
    fi
  fi
  # (6) Reclaim the per-wallet policy storage deposit (refunds to PARENT). A NEAR implicit address IS
  # its ed25519 public-key hex, so the wallet_pubkey is ed25519:<addr>. "not found" (no policy /
  # already removed) is fine — best-effort.
  near_tty "near contract call-function as-transaction \"$CONTRACT_ID\" delete_wallet_policy json-args '$(jq -nc --arg pk "ed25519:$addr" '{wallet_pubkey:$pk}')' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as \"$PARENT\" network-config \"$NETWORK\" sign-with-keychain send" \
    || warn "sweep: $addr — delete_wallet_policy failed (no policy or already removed?)"
}

# sweep_now — drain every sub-wallet currently in the WORKING set, then truncate it (so the same
# wallet is never swept twice across the per-test / abort / final passes). No-op unless --apply.
sweep_now() {
  [[ "$APPLY" == true ]] || return 0
  [[ -s "$SWEEP_QUEUE" ]] || return 0
  log "Returning funds from $(wc -l < "$SWEEP_QUEUE" | tr -d ' ') sub-wallet(s) → $PARENT"
  local e seed addr wid
  # Redirect form (not `cat | while`): the loop runs in the MAIN shell so sweep_one's side effects
  # and any future array mutations are NOT trapped in a pipe subshell.
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    seed=${e%%|*}; addr=${e##*|}; wid=${e#*|}; wid=${wid%%|*}
    sweep_one "$seed" "$wid" "$addr"
  done < "$SWEEP_QUEUE"
  : > "$SWEEP_QUEUE"
}

# return_test_funds — called at the END of each real-money test to drain its sub-wallets immediately
# (don't hold value across tests). Just the working-set sweep.
return_test_funds() { sweep_now; }

# residual_of <addr> → "<native_yocto> <intents_wnear_yocto>" (both "0" if the account is absent/errored
# or holds nothing). Single source of truth for the verify pass's balance read.
residual_of() {
  local a=$1 rpc acct_err native intents
  rpc=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$a\"}}" 2>/dev/null || echo '')
  acct_err=$(echo "$rpc" | jq -r '.error // .result.error // empty' 2>/dev/null)
  native=$(echo "$rpc" | jq -r '.result.amount // "0"' 2>/dev/null || echo "0")
  [[ -n "$acct_err" || -z "$native" ]] && native="0"
  if [[ "$NETWORK" == "mainnet" ]]; then intents=$(intents_wnear "$a"); else intents="0"; fi
  [[ -n "$intents" ]] || intents="0"
  echo "$native $intents"
}
# is_leak <native> <intents> → rc 0 iff native > 0.01 NEAR OR intents is any nonzero amount.
is_leak() { [[ "$(yocto_gt "$1" "$SWEEP_MIN")" == "gt" || ( "$2" != "0" && -n "$2" ) ]]; }

# verify_all_drained — FINAL safety check over the IMMUTABLE ledger. Re-reads native + (mainnet)
# intents for EVERY sub-wallet ever created; any residual native >0.01 NEAR or non-zero intents is a
# LEAK → fail() (recorded, surfaced in the SUMMARY exit code). A sweep's intents-withdraw / DeleteAccount
# settles asynchronously, so a leaky-looking wallet is RE-POLLED (~30s, like the T6/T11/T12 settlement
# polls) before being declared a leak — a genuinely leaked wallet stays nonzero through the poll. Runs
# only under --apply.
verify_all_drained() {
  [[ "$APPLY" == true ]] || return 0
  [[ -s "$RUN_LEDGER" ]] || { log "Balance check: no sub-wallets created"; return 0; }
  local e seed wid addr native intents leaks=0
  # Redirect form (not a pipe) so the loop body runs in the MAIN shell — `leaks` survives the loop.
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    seed=${e%%|*}; addr=${e##*|}; wid=${e#*|}; wid=${wid%%|*}
    read -r native intents < <(residual_of "$addr")
    if is_leak "$native" "$intents"; then
      for _ in $(seq 1 10); do sleep 3; read -r native intents < <(residual_of "$addr"); is_leak "$native" "$intents" || break; done
    fi
    if is_leak "$native" "$intents"; then
      fail "LEAK: $addr native=$native intents=$intents — recover via seed '$seed' (saved in $SEED_LOG)"; leaks=$((leaks+1))
    else
      note "drained: $addr"
    fi
  done < "$RUN_LEDGER"
  log "Balance check: $(wc -l < "$RUN_LEDGER" | tr -d ' ') sub-wallet(s) verified, $leaks leak(s)"
}

# cleanup_subwallets — EXIT trap / abort safety net. The per-test return_test_funds and the final
# sweep_now before SUMMARY already drain wallets on the happy path; this catches anything left when
# the run aborts early (e.g. the real-money fail-fast `exit 1`) or any trailing untracked wallet.
# Best-effort, never fails the suite, no-op unless --apply.
cleanup_subwallets() {
  [[ "$APPLY" == true ]] || return 0
  sweep_now
}

# store_policy <seed> <wallet_id> <policy_json_without_wallet_id>
store_policy() {
  local seed=$1 wid=$2 pol=$3
  local body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(echo "$enc" | jq -r '.encrypted_base64 // empty'); [[ -n "$encb64" ]] || { echo "encrypt-policy failed: $enc" >&2; return 1; }
  # `caller` is SIGNED: the answer is good only for the account that sends the
  # store below, which is $PARENT here.
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(echo "$sg" | jq -r '.signature_hex // empty'); pub_hex=$(echo "$sg" | jq -r '.public_key_hex // empty')
  [[ -n "$sig_hex" ]] || { echo "sign-policy failed: $sg" >&2; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" || return 1
  sleep 5
}

# post <method> <path> <seed> <json|''> → sets HTTP + BODY
HTTP=""; BODY=""
post() {
  local method=$1 path=$2 seed=$3 data=${4:-}
  local args=(-sS -o /tmp/uop.body -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" -H "$(AUTH "$seed")")
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' -d "$data")
  HTTP=$(curl "${args[@]}"); BODY=$(cat /tmp/uop.body)
}

# assert_funded <label> — call right after a funding `post`. Without this a failed funding sub-step
# is silent and only surfaces much later as a confusing "have 0 balance". Treat it as a HARD failure
# here, printing the body so the real cause is visible at the funding step.
assert_funded() {
  local label=$1 st err
  # A failed funding sub-step surfaces three ways across coordinator versions:
  #   legacy:  HTTP 200 + {"status":"failed"}            (a reverted tx returned 2xx)
  #   current: HTTP 422 + {"error":"onchain_tx_failed"}  (revert; survives Cloudflare)
  #   rejected/transient: any other non-2xx (500 NotEnoughBalance, 503, …)
  if [[ "$HTTP" != 2?? ]]; then
    fail "$label funding step HTTP $HTTP — $(echo "$BODY" | head -c200)"; return 1
  fi
  st=$(echo "$BODY"  | jq -r '.status // empty' 2>/dev/null)
  err=$(echo "$BODY" | jq -r '.error  // empty' 2>/dev/null)
  if [[ "$st" == "failed" || "$err" == "onchain_tx_failed" ]]; then
    fail "$label funding step failed — $(echo "$BODY" | head -c200)"; return 1
  fi
  return 0
}

# --quiet: the receiver is usually a FRESH implicit account, and near-cli-rs answers a
# does-not-exist warning with an interactive prompt — headless (no TTY) that dies with
# "The input device is not a TTY" and the sub-wallet is silently never funded.
fund_near() { near_tty "near --quiet tokens $PARENT send-near $1 '$2' network-config $NETWORK sign-with-keychain send"; }

# ─── a secret left for an agent (V6) ──────────────────────────────────────────

# fund_fresh <account_id> <amount> — fund_near for a receiver that does not
# exist yet. near-cli-rs asks a human to confirm before sending to an account it
# cannot find: headless that aborts with "the input device is not a TTY", and in
# a terminal it stops the run waiting for an answer. `--quiet` gives the answer
# up front, which for an implicit account this run has just registered is the
# only answer there is.
fund_fresh() { near_tty "near --quiet tokens $PARENT send-near $1 '$2' network-config $NETWORK sign-with-keychain send"; }

# store_agent_secret_cli <wallet_key> <secrets_json> [extra flags…] — the real
# user path, attempted twice.
#
# A store for the same (project, agent) UPDATES one entry rather than adding a
# second, so retrying after an answer that never came back cannot double
# anything: at worst the same bytes are written again and the contract refunds
# the difference. Without the retry a single dropped response — testnet RPC lost
# one mid-run — reads as "the paying path does not work".
store_agent_secret_cli() {
  local wk=$1 secrets=$2 i; shift 2
  for i in 1 2; do
    OUTLAYER_WALLET_KEY="$wk" "$OUTLAYER_BIN" secrets set-for-agent "$secrets" \
      --project "$CONNECTOR_PROJECT_ID" "$@" >&2 && return 0
    [[ $i -eq 1 ]] && warn "set-for-agent did not go through — retrying once"
  done
  return 1
}

# agent_secret_pubkey <wk_> <project_id> → the endpoint's JSON ("{}" on any error).
agent_secret_pubkey() {
  curl -sS -G "$COORDINATOR_URL/wallet/v1/agent-secret/pubkey" \
    --data-urlencode "project_id=$2" -H "Authorization: Bearer $1" 2>/dev/null || echo '{}'
}

# view_contract <method> <args_json> → the view's JSON text ("null" on any error).
view_contract() {
  local method=$1 b64
  b64=$(printf '%s' "$2" | base64 | tr -d '\n')
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$CONTRACT_ID" --arg m "$method" --arg a "$b64" \
          '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}

# agent_secret_view <agent_account> → the chain's `get_secret_with_vault`, polled.
#
# A store returns once the transaction has EXECUTED, while a view at `final`
# finality reads a block or two behind it. Read straight after a store, the chain
# will truthfully say there is nothing there — so wait for it rather than call
# the store a failure.
agent_secret_view() {
  local agent=$1 args res i
  args=$(jq -nc --arg p "$CONNECTOR_PROJECT_ID" --arg a "$agent" \
    '{accessor:{Project:{project_id:$p}}, profile:$a, owner:$a}')
  for i in 1 2 3 4 5 6 7 8 9 10; do
    res=$(view_contract get_secret_with_vault "$args")
    [[ -n "$(echo "$res" | jq -r '.profile.encrypted_secrets // empty' 2>/dev/null)" ]] && break
    sleep 2
  done
  echo "$res"
}

# assert_agent_secret <label> <agent_account> — what the CHAIN says landed, which
# is the only account of it that does not come from the party being tested: the
# secret exists under the agent's own name, carries the vault binding, and holds
# an ECIES v1 blob rather than whatever bytes happened to be sent.
assert_agent_secret() {
  local label=$1 agent=$2 res bound ct raw first len
  res=$(agent_secret_view "$agent")
  ct=$(echo "$res" | jq -r '.profile.encrypted_secrets // empty' 2>/dev/null)
  bound=$(echo "$res" | jq -r '.vault_id // "null"' 2>/dev/null)

  if [[ -z "$ct" ]]; then
    fail "$label no secret on chain for $agent under $CONNECTOR_PROJECT_ID: $(echo "$res" | head -c200)"
    return 1
  fi
  pass "$label the secret is on chain, named after the agent ($agent)"

  if [[ "$bound" == "$VAULT_ID" ]]; then
    pass "$label the chain binds it to $VAULT_ID — the vault's master is what decrypts it"
  else
    fail "$label vault binding is '$bound', not '$VAULT_ID' — the ciphertext would be handed to the wrong master"
  fi

  # ECIES v1: [0x01 | ephemeral x25519 pub(32) | nonce(12) | ciphertext | tag(16)]
  raw=$(printf '%s' "$ct" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')
  first=${raw:0:2}
  len=$(( ${#raw} / 2 ))
  if [[ "$first" == "01" && $len -ge 61 ]]; then
    pass "$label the stored bytes are an ECIES v1 blob ($len bytes)"
  else
    fail "$label the stored bytes are not ECIES v1 (first byte 0x$first, $len bytes) — nothing will decrypt them"
  fi
}

# store_agent_secret_as_parent <args_json> → rc 0 iff the call LANDED AND SUCCEEDED.
# near-cli-rs's exit code is checked first, and its output second: a contract
# panic that it still exits 0 on would otherwise read as an acceptance, which for
# the negative half of V6f is the answer that must never be faked.
store_agent_secret_as_parent() {
  local out rc=0
  out=$(near_tty "near contract call-function as-transaction $CONTRACT_ID store_agent_secret json-args '$1' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" 2>&1) || rc=$?
  if [[ $rc -ne 0 ]]; then return 1; fi
  if echo "$out" | grep -qiE "error|panicked|failure"; then return 1; fi
  return 0
}

# ─── register BENEFICIARY on wNEAR (mainnet) ───────────────────────────────────
# The intents-balance sweeps (sweep_one step 4 / T6) withdraw wNEAR to BENEFICIARY, which requires
# BENEFICIARY to be storage-registered on the wNEAR (defuse) contract — otherwise the ft_transfer leg
# of the withdraw is rejected and the swept funds would bounce. Ensure BENEFICIARY is wNEAR-registered
# once, best-effort, up front, so the sweep's intents-withdraw can land. PARENT pays the 0.00125 to
# register it (storage_deposit may be paid by anyone for any account_id). Only on mainnet (testnet has
# no intents sweeps) and only under --apply. Placed AFTER every helper (intents_wnear/store_policy/
# post/sweep_one) is defined so definitions-before-use holds.
if [[ "$APPLY" == true && "$NETWORK" == mainnet ]]; then
  PSB=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$WNEAR" --arg a "$BENEFICIARY" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"storage_balance_of",args_base64:({account_id:$a}|tojson|@base64)}}')" 2>/dev/null \
    | jq -r '.result.result // empty | implode' 2>/dev/null || echo '')
  if [[ -z "$PSB" || "$PSB" == "null" ]]; then
    note "BENEFICIARY ($BENEFICIARY) not storage-registered on $WNEAR — registering (so intents sweeps can land)"
    near_tty "near contract call-function as-transaction $WNEAR storage_deposit json-args '$(jq -nc --arg a "$BENEFICIARY" '{account_id:$a}')' prepaid-gas '30 Tgas' attached-deposit '0.00125 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" \
      || warn "BENEFICIARY wNEAR storage_deposit failed — intents sweeps may not land"
  else
    note "BENEFICIARY ($BENEFICIARY) already storage-registered on $WNEAR ($PSB) — intents sweeps can land"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# VAULT-MODE GATE — V1–V5 all need a dedicated, deployable vault.
# Without MPC_PUBLIC_KEY (default-vault mode) there is no per-vault to isolate/recover/retire, so the
# whole suite SKIP-notes cleanly (mirrors unified_op_e2e.sh's default-vault handling of its vault-only
# dimensions). The shared vault block above already deployed VAULT_ID iff MPC_PUBLIC_KEY was set.
# ════════════════════════════════════════════════════════════════════════════════
VAULT_MODE=false
if [[ -n "${MPC_PUBLIC_KEY:-}" && -n "$VAULT_ID" ]]; then
  VAULT_MODE=true
else
  warn "VAULT MODE OFF (no MPC_PUBLIC_KEY): V1–V5 are vault-mode/recovery tests and will be SKIP-noted."
  warn "       Set MPC_PUBLIC_KEY=bls12381g2:... (the keystore-worker value) to deploy vaults + run them."
fi

# MPC-recovery params (testnet) for the sovereign-exit re-derivation chain (V3/V4/V5).
MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer-prod.testnet}"
NEARBLOCKS_URL="${NEARBLOCKS_URL:-https://api-testnet.nearblocks.io}"

# deploy_throwaway_vault <subaccount-name> → echoes "<vault_id>" on stdout (logs to stderr).
# The argument is the FULL, VALID, STABLE subaccount label (e.g. v3v / v4v / v5v / vaultb) — NOT a
# timestamped prefix. A stable name is required so a re-run REUSES the already-deployed vault instead
# of locking fresh stake (the CLI's `--name` is honored here: the vault lands at `<name>.$PARENT`).
#
# --apply-GATED: in dry-run this is never called (the V1–V5 bodies are all under VAULT_MODE, which is
# false without --apply), but guard anyway so an accidental dry-run call deploys nothing.
# Reuse-or-deploy: view_account first; if it exists, resume idempotently and return; else init with
# --exit-window 24h (60s is INVALID — the CLI only accepts 24h/7d/30d). Same init+resume race handling
# as the shared vault block. Used by V1 (two scopes) / V3 / V4 / V5 (each needs its own vault).
deploy_throwaway_vault() {
  local name=$1 id rc out
  id="$name.$PARENT"
  if [[ "$APPLY" != true ]]; then
    note "dry-run: NOT deploying throwaway vault $id (would lock NEAR)" >&2
    return 1
  fi
  if account_exists "$id"; then
    note "throwaway vault $id already on chain — reusing (no new stake); running vault resume idempotently" >&2
    outlayer vault resume "$id" >&2 || warn "vault resume $id failed (already registered?) — continuing" >&2
    outlayer vault status "$id" >/dev/null 2>&1 || { echo "✗ vault.status failed for $id" >&2; return 1; }
    echo "$id"
    return 0
  fi
  log "Deploy throwaway vault $id (--name $name --exit-window 24h)" >&2
  rc=0
  out=$(outlayer vault init --name "$name" --exit-window 24h 2>&1) || rc=$?
  if [[ $rc -ne 0 ]] && echo "$out" | grep -q "outlayer vault resume"; then
    for _ in 1 2 3 4 5; do sleep 6; if outlayer vault resume "$id" >&2; then rc=0; break; fi; done
  fi
  [[ $rc -eq 0 ]] || { echo "✗ throwaway vault init failed for $id: $out" >&2; return 1; }
  outlayer vault status "$id" >/dev/null 2>&1 || { echo "✗ vault.status failed for $id" >&2; return 1; }
  echo "$id"
}

# mk_token_v <seed> <vault_id|''> → Bearer-near token under an ARBITRARY vault scope (mk_token always
# uses the shared VAULT_ID; the isolation/recovery tests need tokens under their own throwaway vaults).
mk_token_v() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1" ${2:+--vault-id "$2"}; }

# vault_state <vault_id> → echoes the vault's get_state JSON ("{}" on any RPC/decode error).
vault_state() {
  local vid=$1
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"$vid\",\"method_name\":\"get_state\",\"args_base64\":\"e30=\"}}" \
    | jq -r '.result.result | implode' 2>/dev/null || echo '{}'
}

# assert_recovery_in_flight <vault_id> <label> — sanity check right after `initiate-unilateral-recovery`
# (and BEFORE the 60s exit window elapses): the on-chain state must show a recovery in progress
# (`recovery != null`) while the vault is STILL locked (`unlocked == false`). V3/V4/V5 then wait for the
# window (wait_finalizable) and finalize_recovery in the same run — this assert is the in-flight midpoint,
# not the end state.
assert_recovery_in_flight() {
  local vid=$1 label=$2 st rec unlocked fafter i
  # The initiate tx just landed; the get_state view (final finality) lags it a block or two → POLL ~24s
  # until recovery!=null. This also primes the subsequent wait_finalizable read (which expects it set).
  for i in 1 2 3 4 5 6 7 8; do
    st=$(vault_state "$vid")
    rec=$(echo "$st" | jq -r '.recovery // empty' 2>/dev/null)
    unlocked=$(echo "$st" | jq -r '.unlocked // empty' 2>/dev/null)
    fafter=$(echo "$st" | jq -r '.recovery.finalize_after // empty' 2>/dev/null)
    # get_state OMITS `unlocked` while the vault is locked (it only serializes as true post-finalize),
    # so "still locked" = unlocked != "true" (absent OR false), NOT == "false".
    [[ -n "$rec" && "$rec" != "null" && "$unlocked" != "true" ]] && { pass "$label recovery in flight on chain (recovery!=null, not unlocked; finalize_after=$fafter)"; return 0; }
    sleep 3
  done
  fail "$label recovery NOT in flight after initiate + ~24s poll (recovery='$rec' unlocked='$unlocked'): $(echo "$st" | head -c200)"
  return 1
}

# set_exit_window_60s <vault_id> <label> — shrink the throwaway vault's unilateral exit window to 60s
# via a DIRECT parent-signed contract call. The `outlayer vault init`/`set-exit-window` CLI reject any
# value < 24h, but the TESTNET vault WASM is the `test-timing` build whose MIN_UNILATERAL_EXIT_WINDOW_SECS
# is 60 (VERIFIED live — it logs `exit_window_set_to_60_secs`). MUST be called BEFORE
# initiate-unilateral-recovery: the contract freezes `finalize_after = now + unilateral_exit_window_secs`
# at INITIATE time (set_exit_window does NOT retro-shrink an in-flight recovery — see vault-contract
# lib.rs unilateral_initiate_recovery / set_exit_window). set_exit_window is parent-gated, so the PARENT
# keychain signs it. Only meaningful for V3/V4/V5 (the finalize tests); --apply-gated by its callers.
set_exit_window_60s() {
  local vid=$1 label=$2
  log "$label set unilateral exit window → 60s on $vid (direct set_exit_window — CLI rejects <24h; test-timing build min is 60s)"
  near_tty "near contract call-function as-transaction \"$vid\" set_exit_window json-args '{\"new_window_secs\":60}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as \"$PARENT\" network-config \"$NETWORK\" sign-with-keychain send" \
    || fail "$label set_exit_window(60) failed on $vid (is the deployed WASM the test-timing build? mainnet build rejects <24h)"
  # Let the parent access-key nonce propagate before the caller's back-to-back initiate tx — set_exit_window
  # (near-cli) and initiate-unilateral-recovery (outlayer CLI) share the PARENT key; without a gap the 2nd
  # fetches a stale access-key nonce → InvalidNonce. vault_initiate_retry below is the belt to this suspenders.
  sleep 4
}

# vault_initiate_retry <vault_id> <label> — initiate-unilateral-recovery, retrying on the parent-key nonce
# race: set_exit_window (near-cli) + initiate (outlayer CLI) are back-to-back txs from the SAME parent key,
# so the 2nd can read a stale access-key nonce → InvalidNonce. Retry up to 5× with a settle; any
# non-nonce error fails loudly. Freezing finalize_after at initiate is unaffected (the 60s window persists).
vault_initiate_retry() {
  local vid=$1 label=$2 i out rc
  for i in 1 2 3 4 5; do
    rc=0; out=$(outlayer vault initiate-unilateral-recovery "$vid" 2>&1) || rc=$?
    [[ $rc -eq 0 ]] && { echo "$out" >&2; return 0; }
    if echo "$out" | grep -qiE 'invalidnonce|nonce'; then note "$label initiate: parent-key nonce race (try $i/5) — settling 5s"; sleep 5; continue; fi
    echo "$out" >&2; fail "$label initiate-unilateral-recovery failed: $(echo "$out" | tail -3 | tr '\n' ' ' | head -c200)"; return 1
  done
  fail "$label initiate-unilateral-recovery still InvalidNonce after 5 retries"; return 1
}

# wait_finalizable <vault_id> <label> — block until the in-flight recovery's `finalize_after` has
# elapsed so `finalize_recovery` will be accepted. JUSTIFIED contract-timing wait (the chain enforces a
# 60s exit window before finalize is legal — there is no event to await, only wall-clock against the
# on-chain `finalize_after` timestamp). Polls get_state every 6s up to ~13× (~78s > the 60s window +
# block-time slack); succeeds as soon as block_timestamp ≥ recovery.finalize_after, else fails loudly.
# Reads finalize_after (ns) from get_state and compares against the latest block timestamp (also ns).
wait_finalizable() {
  local vid=$1 label=$2 st fa now_ns i
  st=$(vault_state "$vid")
  fa=$(echo "$st" | jq -r '.recovery.finalize_after // empty' 2>/dev/null)
  [[ -n "$fa" && "$fa" != "null" ]] || { fail "$label wait_finalizable: no recovery.finalize_after in state: $(echo "$st" | head -c160)"; return 1; }
  log "$label waiting for the 60s exit window to elapse before finalize (justified on-chain-timing wait; finalize_after=$fa ns)"
  for i in $(seq 1 13); do
    now_ns=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"block","params":{"finality":"final"}}' 2>/dev/null \
      | jq -r '.result.header.timestamp // empty' 2>/dev/null)
    if [[ -n "$now_ns" && "$now_ns" != "null" ]]; then
      # ns magnitudes (~1e18) exceed bash 64-bit safe range only marginally; compare as decimal strings
      # via the same length-then-lexicographic comparator used for yocto.
      [[ "$(yocto_gt "$now_ns" "$fa")" == "gt" || "$now_ns" == "$fa" ]] && { note "$label exit window elapsed (block ts $now_ns ≥ finalize_after $fa)"; return 0; }
    fi
    sleep 6
  done
  note "$label exit-window poll exhausted (~78s) — proceeding to finalize anyway; the contract is the final arbiter of finalize_after"
  return 0
}

# finalize_and_assert_unlocked <vault_id> <new_parent_pubkey> <label> — call finalize_recovery (install
# the customer's locally-generated key) and poll get_state().unlocked == true. The `unlocked=true` flip
# + `recovery=None` clear are DEFERRED to the contract's callback_after_swap (the atomic
# DeleteKey(TEE)+AddFullAccessKey(new_parent) promise resolves a block or two later), so poll ~30s at
# FINAL finality — identical to the legacy bearer_near_recovery_e2e.sh / sovereignty_e2e.sh / vault_detach_test.sh
# post-finalize loop. fail()s if the swap never commits. On success the vault is RETIRED (irreversible).
finalize_and_assert_unlocked() {
  local vid=$1 newpub=$2 label=$3 unlocked st
  log "$label finalize_recovery — atomic on-chain key-swap (DeleteKey(TEE)+AddFullAccessKey), installs $newpub"
  outlayer vault finalize-recovery "$vid" "$newpub" >&2 || { fail "$label finalize-recovery failed"; return 1; }
  unlocked=false
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    st=$(vault_state "$vid")
    unlocked=$(echo "$st" | jq -r '.unlocked // empty' 2>/dev/null)
    [[ "$unlocked" == "true" ]] && break
    sleep 3
  done
  [[ "$unlocked" == "true" ]] || { fail "$label vault.unlocked did not flip true after finalize + ~30s — atomic swap did not commit: $(echo "$st" | head -c160)"; return 1; }
  RETIRED_VAULTS+=("$vid")
  pass "$label vault.unlocked == true on chain — vault RETIRED (irreversible; OutLayer TEE keys deleted)"
  return 0
}

# Best-effort: track every VAULT this run touched (deployed OR reused) so the final summary can
# re-state which vaults exist + their stake. Seeded with the shared VAULT_ID (vault.$PARENT) so the
# summary accounts for it too. (Vaults are NOT auto-deleted; deletion is an operator decision, out of
# scope.) The SHARED/V1 vaults (vault.$PARENT, vaultb.$PARENT) are NEVER finalized → stay reusable.
# The V3/V4/V5 THROWAWAY vaults (v3v/v4v/v5v.$PARENT) ARE finalized → RETIRED (unlocked, OutLayer TEE
# keys deleted, irreversible): they are tracked separately in RETIRED_VAULTS so the summary is honest.
THROWAWAY_VAULTS=()
[[ -n "$VAULT_ID" ]] && THROWAWAY_VAULTS+=("$VAULT_ID")
# Vaults that V3/V4/V5 RETIRED via finalize_recovery this run (irreversible). Surfaced in the summary.
RETIRED_VAULTS=()

# ════════════════════════════════════════════════════════════════════════════════
# V1 — multi-customer vault isolation  [VAULT/POLICY] (no funds)
#       Ported from tests/vault_multi_customer_isolation.sh. Two DISTINCT vault scopes under the SAME
#       parent must derive DIFFERENT sub-wallet addresses (per-vault master is HMAC-keyed differently),
#       and a client-supplied `X-Customer-Vault` header must be IGNORED — vault scope is AUTH-driven
#       (the Bearer-near token's vault_id), not request-driven. Asserts:
#         1a  two throwaway vaults (A, B) under PARENT → same seed derives DIFFERENT addresses;
#         1b  the two scopes also sign with DIFFERENT public keys (crypto isolation, not just addr);
#         1c  a request under scope A but carrying `X-Customer-Vault: <vault B>` still returns A's
#             address — the header is decorative / ignored at the authenticated endpoint.
#       NOTE: the source minted per-vault wk_ via POST /register {vault_id}; here we drive the same
#       isolation via Bearer-near tokens scoped to each vault (the headless auth path the suite uses),
#       which exercises the identical keystore derive(customer=vault, seed) partitioning.
# ════════════════════════════════════════════════════════════════════════════════
if want V1; then
  if [[ "$VAULT_MODE" == true ]]; then
    log "V1 [VAULT/POLICY] multi-customer vault isolation — two scopes → distinct addrs; X-Customer-Vault ignored"
    # Scope A = the shared vault.$PARENT (already deployed/reused above). Scope B = a SECOND valid-named
    # vault (vaultb.$PARENT), deployed/reused here (--apply-gated, exit-window 24h). Two DISTINCT scopes
    # under the same parent must derive different addresses — no finalize_recovery, so neither is retired.
    V1_VA="$VAULT_ID"
    V1_VB=$(deploy_throwaway_vault "vaultb") || fail "V1 deploy vault B (vaultb.$PARENT)"
    if [[ -n "${V1_VA:-}" && -n "${V1_VB:-}" && "$V1_VA" != "$V1_VB" ]]; then
      THROWAWAY_VAULTS+=("$V1_VB")
      pass "V1 two vaults under $PARENT: A=$V1_VA B=$V1_VB"
      ISO_SEED="v1-iso-$(date +%s)-$$"

      # 1a: same seed, different vault scope → DIFFERENT derived address.
      ADDR_A=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "Authorization: Bearer near:$(mk_token_v "$ISO_SEED" "$V1_VA")" | jq -r '.address // empty')
      ADDR_B=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "Authorization: Bearer near:$(mk_token_v "$ISO_SEED" "$V1_VB")" | jq -r '.address // empty')
      [[ -n "$ADDR_A" && -n "$ADDR_B" ]] || fail "V1a /address returned empty for one scope (A='$ADDR_A' B='$ADDR_B')"
      note "V1a addrA=$ADDR_A addrB=$ADDR_B"
      [[ "$ADDR_A" != "$ADDR_B" ]] && pass "V1a distinct vault scopes → distinct addresses (per-vault master honored)" \
        || fail "V1a ISOLATION BROKEN: both vaults derived the same address $ADDR_A (same master for distinct scopes)"

      # 1b: the two scopes sign with DIFFERENT public keys (independent keys, not just distinct addrs).
      SM_A=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer near:$(mk_token_v "$ISO_SEED" "$V1_VA")" -H 'Content-Type: application/json' -d '{"message":"v1-isolation-check","recipient":"iso-verifier.testnet","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
      SM_B=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer near:$(mk_token_v "$ISO_SEED" "$V1_VB")" -H 'Content-Type: application/json' -d '{"message":"v1-isolation-check","recipient":"iso-verifier.testnet","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
      PUB_A=$(echo "$SM_A" | jq -r '.public_key // empty'); PUB_B=$(echo "$SM_B" | jq -r '.public_key // empty')
      [[ -n "$PUB_A" && -n "$PUB_B" ]] || fail "V1b sign-message returned no pubkey for one scope (A='$PUB_A' B='$PUB_B')"
      [[ "$PUB_A" != "$PUB_B" ]] && pass "V1b signing pubkeys differ ($PUB_A vs $PUB_B)" \
        || fail "V1b ISOLATION BROKEN: both scopes signed with the same public key $PUB_A"

      # 1c: X-Customer-Vault header IGNORED — scope A token + header→B must still return A's address.
      ADDR_PROBE=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
        -H "Authorization: Bearer near:$(mk_token_v "$ISO_SEED" "$V1_VA")" -H "X-Customer-Vault: $V1_VB" | jq -r '.address // empty')
      note "V1c /address (scope A, header→B) = $ADDR_PROBE (expect A=$ADDR_A)"
      [[ "$ADDR_PROBE" == "$ADDR_A" ]] && pass "V1c X-Customer-Vault header IGNORED — vault scope is auth-bound, not request-driven" \
        || fail "V1c HEADER NOT IGNORED: scope A returned $ADDR_PROBE (vault B's master?) instead of $ADDR_A"
    fi
  else
    note "V1 SKIPPED (vault mode off): multi-customer isolation needs two DEPLOYED per-vaults — set MPC_PUBLIC_KEY"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# V2 — N wallets per ONE vault  [VAULT/POLICY] (no funds)
#       Ported from tests/multi_wallet_vault_e2e.sh. A single sovereign vault backs arbitrarily many
#       independent custody wallets, each with its own wallet_id + derived address, all reporting the
#       same vault_id; and a sub-agent minted under one of those wallets inherits the vault binding.
#       Asserts (over the shared VAULT_ID, N=3 by default):
#         2a  N independent sub-wallets (distinct seeds) → N DISTINCT wallet_ids;
#         2b  → N DISTINCT addresses (per-wallet derivation under one vault master);
#         2c  each sub-wallet's /address reports vault_id == VAULT_ID;
#         2d  a sub-agent (PUT /wallet/v1/api-key from a parent wk_) inherits vault_id == VAULT_ID and
#             derives a DIFFERENT address from its parent (the fan-out).
#       NOTE: the source minted parents via POST /register {vault_id} (→ wk_) and the sub-agent via the
#       recipe sub_key=wk_+sha256("<seed>:0:<parent_key>"). Both are preserved here, scoped to the
#       suite's shared throwaway VAULT_ID.
# ════════════════════════════════════════════════════════════════════════════════
if want V2; then
  if [[ "$VAULT_MODE" == true ]]; then
    log "V2 [VAULT/POLICY] N wallets per one vault — distinct wallet_id+addr each; sub-agent inherits binding"
    N_WALLETS="${N_WALLETS:-3}"
    declare -a V2_WK=() V2_WID=() V2_ADDR=()
    ok=true
    for i in $(seq 1 "$N_WALLETS"); do
      RESP=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d "$(jq -nc --arg v "$VAULT_ID" '{vault_id:$v}')")
      WK=$(echo "$RESP" | jq -r '.api_key // empty'); WID=$(echo "$RESP" | jq -r '.wallet_id // empty'); ADDR=$(echo "$RESP" | jq -r '.near_account_id // empty')
      if [[ -z "$WK" || "$WK" != wk_* ]]; then fail "V2 /register #$i returned no wk_ api_key: $(echo "$RESP" | head -c160)"; ok=false; break; fi
      V2_WK+=("$WK"); V2_WID+=("$WID"); V2_ADDR+=("$ADDR")
      note "V2 wallet #$i: wallet_id=$WID addr=$ADDR"
    done
    if [[ "$ok" == true ]]; then
      # 2a: distinct wallet_ids.
      UNIQ_WID=$(printf '%s\n' "${V2_WID[@]}" | sort -u | wc -l | tr -d ' ')
      [[ "$UNIQ_WID" == "$N_WALLETS" ]] && pass "V2a $N_WALLETS distinct wallet_ids under one vault" || fail "V2a expected $N_WALLETS distinct wallet_ids, got $UNIQ_WID"
      # 2b: distinct addresses.
      UNIQ_ADDR=$(printf '%s\n' "${V2_ADDR[@]}" | sort -u | wc -l | tr -d ' ')
      [[ "$UNIQ_ADDR" == "$N_WALLETS" ]] && pass "V2b $N_WALLETS distinct addresses (per-wallet derivation under same vault master)" || fail "V2b expected $N_WALLETS distinct addresses, got $UNIQ_ADDR"
      # 2c: each wk_ /address reports vault_id == VAULT_ID.
      allvault=true
      for i in $(seq 1 "$N_WALLETS"); do
        idx=$((i-1))
        GOT_VAULT=$(curl -sS -H "Authorization: Bearer ${V2_WK[$idx]}" "$COORDINATOR_URL/wallet/v1/address?chain=near" | jq -r '.vault_id // empty')
        [[ "$GOT_VAULT" == "$VAULT_ID" ]] || { fail "V2c wallet #$i /address vault_id='$GOT_VAULT' != '$VAULT_ID'"; allvault=false; }
      done
      [[ "$allvault" == true ]] && pass "V2c all $N_WALLETS wallets report vault_id=$VAULT_ID"

      # 2d: sub-agent under wallet #1 inherits the vault binding + derives a different address.
      PARENT_KEY="${V2_WK[0]}"
      SUB_SEED="${SUB_AGENT_SEED:-v2-sub-1-$(date +%s)-$$}"
      # Recipe (agent-custody skill): sub_key = wk_ + sha256("<seed>:0:<parent_key>"); key_hash = sha256(sub_key).
      SUB_KEY="wk_$(printf '%s:0:%s' "$SUB_SEED" "$PARENT_KEY" | shasum -a 256 | awk '{print $1}')"
      KEY_HASH=$(printf '%s' "$SUB_KEY" | shasum -a 256 | awk '{print $1}')
      curl -sS -X PUT "$COORDINATOR_URL/wallet/v1/api-key" -H "Authorization: Bearer $PARENT_KEY" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg s "$SUB_SEED" --arg kh "$KEY_HASH" '{seed:$s, key_hash:$kh}')" >/dev/null
      SUB_RESP=$(curl -sS -H "Authorization: Bearer $SUB_KEY" "$COORDINATOR_URL/wallet/v1/address?chain=near")
      SUB_VAULT=$(echo "$SUB_RESP" | jq -r '.vault_id // empty'); SUB_ADDR=$(echo "$SUB_RESP" | jq -r '.address // empty')
      [[ "$SUB_VAULT" == "$VAULT_ID" ]] && pass "V2d sub-agent inherits vault_id=$VAULT_ID" || fail "V2d sub-agent vault_id='$SUB_VAULT' != '$VAULT_ID': $(echo "$SUB_RESP" | head -c160)"
      [[ -n "$SUB_ADDR" && "$SUB_ADDR" != "${V2_ADDR[0]}" ]] && pass "V2d sub-agent address differs from parent #1 (derivation fanned out)" || fail "V2d sub-agent address '$SUB_ADDR' == parent #1 '${V2_ADDR[0]}' — no fan-out"
    fi
  else
    note "V2 SKIPPED (vault mode off): N-wallets-per-vault needs a DEPLOYED vault to bind wallets to — set MPC_PUBLIC_KEY"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# V3 — Bearer-near sovereign exit  [VAULT/POLICY] (no fund movement beyond ~0.1 NEAR vault stake)
#       Ported from tests/bearer_near_recovery_e2e.sh. The core sovereignty guarantee on the stateless
#       Bearer-near path (tipbot-style: no per-user wk_, no /register). Uses a THROWAWAY vault it
#       RETIRES. Asserts:
#         3a  PRE-RECOVERY: keystore derives + signs for (PARENT, seed, vault) via Bearer-near
#             (/sign-message returns a signature); 3 distinct seeds → 3 distinct addresses;
#         3b  finalize_recovery (atomic FCAK swap) flips vault.unlocked == true on chain;
#         3c  POST-RECOVERY: keystore REFUSES — Bearer-near /address AND /sign-message both fail
#             (assert_serving_allowed rejects on unlocked == true);
#         3d  the customer recovers the per-vault master via MPC CKD using only the NEW parent key,
#             then re-derives EACH user OFFLINE (compute-wallet-id → derive-wallet-key) and the
#             offline address MATCHES the keystore's pre-recovery address — exactly. The value-prop.
# ════════════════════════════════════════════════════════════════════════════════
if want V3; then
  if [[ "$VAULT_MODE" == true ]]; then
    log "V3 [VAULT/POLICY] Bearer-near sovereign exit — FULL single-run (derive → 60s window → finalize → keystore refuses → MPC-CKD offline re-derive matches)"
    warn "V3 finalize_recovery is IRREVERSIBLE — it RETIRES this throwaway vault (unlocked, OutLayer-side TEE keys deleted). NEVER pointed at vault.\$PARENT (uses v3v.\$PARENT)."
    # Distinct VALID subaccount name (v3v.$PARENT); --apply-gated, deploy/reuse, exit-window 24h init
    # (the CLI rejects <24h); V3 shrinks it to 60s via a direct set_exit_window call before initiate.
    V3_VAULT=$(deploy_throwaway_vault "v3v$RUN_TAG") || fail "V3 deploy vault"
    if [[ -n "${V3_VAULT:-}" ]]; then
      THROWAWAY_VAULTS+=("$V3_VAULT")
      pass "V3 throwaway vault $V3_VAULT deployed"

      # Bearer-near helpers scoped to V3_VAULT (return "body\nHTTP:<code>"; caller splits).
      v3_addr() { local seed=$1 r; r=$(curl -sS -w '\nHTTP:%{http_code}' -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "Authorization: Bearer near:$(mk_token_v "$seed" "$V3_VAULT")"); echo "$r"; }
      v3_sign() { local seed=$1 msg=$2; curl -sS -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer near:$(mk_token_v "$seed" "$V3_VAULT")" -H 'Content-Type: application/json' -d "$(jq -nc --arg m "$msg" '{message:$m, recipient:"v3-recov.testnet", nonce:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')"; }

      # 3a: mint 3 distinct users; capture pre-recovery addresses (the derive-sub-wallets work).
      declare -a V3_SEEDS=() V3_ADDRS=()
      v3ok=true
      for i in 1 2 3; do
        s="v3-user-$i-$(date +%s)-$$"; V3_SEEDS+=("$s")
        R=$(v3_addr "$s"); H=$(echo "$R" | tail -1 | sed 's/HTTP://'); B=$(echo "$R" | sed '$d')
        A=$(echo "$B" | jq -r '.address // empty')
        [[ "$H" == "200" && -n "$A" ]] || { fail "V3a user $i mint failed (HTTP $H): $(echo "$B" | head -c160)"; v3ok=false; break; }
        V3_ADDRS+=("$A"); note "V3a user $i: seed=$s addr=$A"
      done
      if [[ "$v3ok" == true ]]; then
        [[ "${V3_ADDRS[0]}" != "${V3_ADDRS[1]}" && "${V3_ADDRS[1]}" != "${V3_ADDRS[2]}" && "${V3_ADDRS[0]}" != "${V3_ADDRS[2]}" ]] \
          && pass "V3a 3 distinct seeds → 3 distinct addresses under $V3_VAULT" || fail "V3a duplicate addresses across distinct seeds — HMAC broken"
        # Pre-recovery sign for user #1 must succeed.
        PR=$(v3_sign "${V3_SEEDS[0]}" "v3-preflight-$(date +%s)"); PRH=$(echo "$PR" | tail -1 | sed 's/HTTP://'); PRB=$(echo "$PR" | sed '$d')
        PRS=$(echo "$PRB" | jq -r '.signature // empty')
        [[ "$PRH" == "200" && -n "$PRS" && "$PRS" != "null" ]] && pass "V3a PRE-RECOVERY keystore signed for user #1 (sig len=${#PRS})" || fail "V3a pre-recovery sign failed (HTTP $PRH): $(echo "$PRB" | head -c160)"

        # 3b: 60s window (direct set_exit_window) → initiate → assert in-flight → wait window → finalize.
        # set_exit_window MUST precede initiate (finalize_after is frozen at initiate from the window).
        set_exit_window_60s "$V3_VAULT" "V3"
        log "V3 initiate unilateral recovery"
        vault_initiate_retry "$V3_VAULT" "V3"
        assert_recovery_in_flight "$V3_VAULT" "V3b"
        wait_finalizable "$V3_VAULT" "V3"
        # Customer generates the sovereign parent key that finalize installs (replaces all TEE keys).
        V3_KEY=$("$RECOVERY_BIN" generate-key)
        V3_NEWPUB=$(echo "$V3_KEY" | jq -r '.public_key'); V3_NEWPRIV=$(echo "$V3_KEY" | jq -r '.private_key')
        [[ -n "$V3_NEWPUB" && -n "$V3_NEWPRIV" ]] || fail "V3 generate-key produced no keypair"
        finalize_and_assert_unlocked "$V3_VAULT" "$V3_NEWPUB" "V3b" || true

        # 3c: POST-RECOVERY the keystore REFUSES — both /address (derive) and /sign-message (sign) must
        # fail (assert_serving_allowed rejects on unlocked == true). bn_address returns non-zero on a
        # non-200, so capture its rc; bn_sign must yield no signature.
        PA=$(v3_addr "${V3_SEEDS[0]}"); PAH=$(echo "$PA" | tail -1 | sed 's/HTTP://')
        [[ "$PAH" != "200" ]] && pass "V3c POST-RECOVERY /address refused (HTTP $PAH) — keystore evicted master, refuses to derive" \
          || fail "V3c POST-RECOVERY /address STILL returned 200 — cutoff broken: $(echo "$PA" | sed '$d' | head -c160)"
        PS=$(v3_sign "${V3_SEEDS[0]}" "v3-post-recovery-attempt"); PSH=$(echo "$PS" | tail -1 | sed 's/HTTP://'); PSB=$(echo "$PS" | sed '$d')
        PSSIG=$(echo "$PSB" | jq -r '.signature // empty' 2>/dev/null || echo "")
        { [[ "$PSH" -ge 400 ]] || [[ -z "$PSSIG" || "$PSSIG" == "null" ]]; } && pass "V3c POST-RECOVERY /sign-message refused (HTTP $PSH) — OutLayer cannot sign for this vault" \
          || fail "V3c POST-RECOVERY keystore STILL signed (HTTP $PSH sig=${PSSIG:0:20}) — cutoff broken"

        # 3d: MPC-CKD recover the per-vault master from the NEW parent key, then re-derive EACH user
        # OFFLINE (compute-wallet-id → derive-wallet-key) and assert the offline near_address MATCHES the
        # keystore's pre-recovery address. The tipbot value-prop: leave OutLayer, recover all users.
        log "V3d recover per-vault master via MPC CKD (new parent key) + offline re-derive all 3 users"
        V3_REC_RC=0
        V3_REC_OUT=$(VAULT_PRIVATE_KEY="$V3_NEWPRIV" "$RECOVERY_BIN" --vault-id "$V3_VAULT" --from-chain \
          --rpc-url "$RPC_URL" --mpc-contract "$MPC_CONTRACT_ID" --nearblocks-url "$NEARBLOCKS_URL" 2>&1) || V3_REC_RC=$?
        echo "$V3_REC_OUT" >&2
        [[ $V3_REC_RC -eq 0 ]] || fail "V3d customer-recovery exited $V3_REC_RC"
        V3_MASTER=$(echo "$V3_REC_OUT" | awk -F= '/^master_hex=/{print $2; exit}')
        [[ -n "$V3_MASTER" && ${#V3_MASTER} -eq 64 ]] || fail "V3d no master_hex (got '${V3_MASTER:0:16}', len ${#V3_MASTER})"
        pass "V3d per-vault master recovered locally (64 hex chars)"
        v3derok=true
        for i in 0 1 2; do
          WID=$("$RECOVERY_BIN" compute-wallet-id --account-id "$PARENT" --seed "${V3_SEEDS[$i]}" --vault-id "$V3_VAULT")
          DERA=$("$RECOVERY_BIN" derive-wallet-key --master "$V3_MASTER" --wallet-id "$WID" | jq -r '.near_address')
          note "V3d user $((i+1)): offline=$DERA keystore=${V3_ADDRS[$i]}"
          [[ "$DERA" == "${V3_ADDRS[$i]}" ]] || { fail "V3d user $((i+1)) DERIVATION MISMATCH: offline=$DERA vs keystore=${V3_ADDRS[$i]}"; v3derok=false; }
        done
        [[ "$v3derok" == true ]] && pass "V3d ALL 3 users re-derived offline; addresses match the keystore exactly — sovereign exit proven"
      fi
    fi
  else
    note "V3 SKIPPED (vault mode off): sovereign exit requires a DEPLOYED vault to finalize_recovery on — set MPC_PUBLIC_KEY"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# V4 — detach secret-decrypt BEFORE/AFTER recovery  [VAULT/POLICY] (no fund movement beyond vault stake)
#       Ported from tests/vault_detach_test.sh. The secrets-side of the sovereign-exit chain on a
#       THROWAWAY vault it RETIRES. Asserts:
#         4a  PRE-RECOVERY: capture the keystore encryption pubkey for (project, vault) via
#             /secrets/pubkey (only possible while locked — the cryptographic ground truth); and a
#             /call decrypt returns the EXPECTED secret value (keystore decrypts via per-vault master);
#         4b  finalize_recovery flips vault.unlocked == true;
#         4c  POST-RECOVERY: the same /call must FAIL to return the secret value (server-side cutoff);
#         4d  recover master via MPC CKD; fetch the on-chain ciphertext (get_secrets view); locally
#             decrypt-secret with (master, seed) → plaintext == EXPECTED_SECRET_VALUE — proving the
#             derivation chain matches the keystore's encrypt side.
#       GATED on V4-specific env (SECRET_PROJECT/SECRET_OWNER/SECRET_PROFILE/EXPECTED_SECRET_VALUE/
#       SECRET_PAYMENT_KEY) being set AND a pre-deployed WASI project. Absent any of them V4 cleanly
#       SKIP-notes — V3/V5 already cover the keystore-level cutoff via the wallet sign/derive path,
#       which shares the same per-vault-master code. The local chacha_key-vs-pubkey comparison the
#       source notes is un-portable (derive-wallet-key uses a wallet seed shape, not the secrets seed
#       shape), so the reachable proof is the decrypt round-trip in 4d.
# ════════════════════════════════════════════════════════════════════════════════
if want V4; then
  if [[ "$VAULT_MODE" != true ]]; then
    note "V4 SKIPPED (vault mode off): secret detach needs a DEPLOYED vault + per-vault-master secret — set MPC_PUBLIC_KEY"
  elif [[ -z "${SECRET_PROJECT:-}" || -z "${SECRET_OWNER:-}" || -z "${SECRET_PROFILE:-}" || -z "${EXPECTED_SECRET_VALUE:-}" || -z "${SECRET_PAYMENT_KEY:-}" ]]; then
    note "V4 SKIPPED — needs SECRET_PROJECT + SECRET_OWNER + SECRET_PROFILE + EXPECTED_SECRET_VALUE + SECRET_PAYMENT_KEY (a pre-deployed WASI project + payment key). The keystore-level cutoff is covered by V3/V5."
  else
    log "V4 [VAULT/POLICY] detach secret-decrypt — FULL single-run (pre-recovery decrypt → 60s window → finalize → /call refused → on-chain ciphertext re-derive + local decrypt match) (project=$SECRET_PROJECT)"
    warn "V4 finalize_recovery is IRREVERSIBLE — it RETIRES this throwaway vault (unlocked, OutLayer-side TEE keys deleted). NEVER pointed at vault.\$PARENT (uses v4v.\$PARENT)."
    # Distinct VALID subaccount name (v4v.$PARENT); --apply-gated, deploy/reuse (exit-window 24h init —
    # CLI rejects <24h); V4 shrinks it to 60s via direct set_exit_window before initiate.
    V4_VAULT=$(deploy_throwaway_vault "v4v$RUN_TAG") || fail "V4 deploy vault"
    if [[ -n "${V4_VAULT:-}" ]]; then
      THROWAWAY_VAULTS+=("$V4_VAULT")
      pass "V4 throwaway vault $V4_VAULT deployed"

      # 4a: capture keystore encryption pubkey (PRE-RECOVERY ground truth) + store a vault-bound secret + pre-recovery /call.
      # Bind a fresh secret to THIS throwaway vault under SECRET_PROFILE so the decrypt path uses V4_VAULT's master.
      log "V4a store secret MY_TEST_SECRET (profile=$SECRET_PROFILE, vault=$V4_VAULT) under $SECRET_PROJECT"
      outlayer secrets set --project "$SECRET_PROJECT" --profile "$SECRET_PROFILE" --vault-id "$V4_VAULT" \
        "$(jq -nc --arg v "$EXPECTED_SECRET_VALUE" '{MY_TEST_SECRET:$v}')" >&2 || fail "V4a outlayer secrets set failed"
      PK_RESP=$(curl -sS -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/secrets/pubkey" -H 'Content-Type: application/json' -H "X-Customer-Vault: $V4_VAULT" \
        -d "$(jq -nc --arg pid "$SECRET_PROJECT" --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" '{accessor:{type:"Project", project_id:$pid}, owner:$owner, profile:$profile, secrets_json:"{\"X\":\"y\"}"}')")
      PK_H=$(echo "$PK_RESP" | tail -1 | sed 's/HTTP://'); PK_B=$(echo "$PK_RESP" | sed '$d')
      KEYSTORE_PUBKEY=$(echo "$PK_B" | jq -r '.pubkey // empty')
      [[ "$PK_H" == "200" && -n "$KEYSTORE_PUBKEY" && "$KEYSTORE_PUBKEY" != "null" ]] && pass "V4a keystore encryption pubkey captured: $KEYSTORE_PUBKEY" || fail "V4a /secrets/pubkey failed (HTTP $PK_H): $(echo "$PK_B" | head -c160)"
      log "V4a PRE-RECOVERY /call/$SECRET_PROJECT (expect '$EXPECTED_SECRET_VALUE')"
      PRE_CALL=$(curl -sS --max-time 90 -X POST "$COORDINATOR_URL/call/$SECRET_PROJECT" -H "X-Payment-Key: $SECRET_PAYMENT_KEY" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" '{input:{command:"get_secret", keys:["MY_TEST_SECRET"]}, secrets_ref:{account_id:$owner, profile:$profile}, async:false}')" 2>&1 || echo '')
      echo "$PRE_CALL" | head -10 >&2
      if echo "$PRE_CALL" | grep -qF "\"value\":\"$EXPECTED_SECRET_VALUE\""; then pass "V4a /call returned the expected secret pre-recovery — keystore can decrypt"; else fail "V4a /call did not return MY_TEST_SECRET=$EXPECTED_SECRET_VALUE pre-recovery: $(echo "$PRE_CALL" | head -c200)"; fi

      # 4b: 60s window (direct set_exit_window) → initiate → assert in-flight → wait window → finalize.
      # set_exit_window MUST precede initiate (finalize_after is frozen at initiate from the window).
      set_exit_window_60s "$V4_VAULT" "V4"
      log "V4 initiate unilateral recovery"
      vault_initiate_retry "$V4_VAULT" "V4"
      assert_recovery_in_flight "$V4_VAULT" "V4b"
      wait_finalizable "$V4_VAULT" "V4"
      V4_KEY=$("$RECOVERY_BIN" generate-key)
      V4_NEWPUB=$(echo "$V4_KEY" | jq -r '.public_key'); V4_NEWPRIV=$(echo "$V4_KEY" | jq -r '.private_key')
      [[ -n "$V4_NEWPUB" && -n "$V4_NEWPRIV" ]] || fail "V4 generate-key produced no keypair"
      finalize_and_assert_unlocked "$V4_VAULT" "$V4_NEWPUB" "V4b" || true

      # 4c: POST-RECOVERY the same /call must FAIL to return the secret value (server-side cutoff — the
      # keystore can no longer decrypt via the per-vault master once unlocked == true).
      log "V4c POST-RECOVERY /call/$SECRET_PROJECT (expect refusal / no secret)"
      POST_CALL_OUT=$(curl -sS --max-time 90 -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/call/$SECRET_PROJECT" -H "X-Payment-Key: $SECRET_PAYMENT_KEY" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" '{input:{command:"get_secret", keys:["MY_TEST_SECRET"]}, secrets_ref:{account_id:$owner, profile:$profile}, async:false}')" 2>&1 || echo '')
      POST_CALL_H=$(echo "$POST_CALL_OUT" | tail -1 | sed 's/HTTP://'); POST_CALL_B=$(echo "$POST_CALL_OUT" | sed '$d')
      echo "$POST_CALL_B" | head -10 >&2
      if echo "$POST_CALL_B" | grep -qF "\"value\":\"$EXPECTED_SECRET_VALUE\""; then
        fail "V4c POST-RECOVERY /call STILL returned the secret value — server-side secret cutoff is broken"
      fi
      pass "V4c /call refused to return the secret post-recovery (HTTP $POST_CALL_H) — secret cutoff confirmed"

      # 4d: recover master via MPC CKD; fetch on-chain ciphertext (get_secrets view); locally decrypt with
      # (master, seed) → plaintext == EXPECTED_SECRET_VALUE. Proves the local derivation chain matches the
      # keystore's encrypt side. Seed shape mirrors keystore-worker for Project accessors.
      SECRET_SEED="project:${SECRET_PROJECT}:${SECRET_OWNER}"
      log "V4d recover per-vault master via MPC CKD + read on-chain ciphertext + local decrypt (seed=$SECRET_SEED)"
      V4_REC_RC=0
      V4_REC_OUT=$(VAULT_PRIVATE_KEY="$V4_NEWPRIV" "$RECOVERY_BIN" --vault-id "$V4_VAULT" --from-chain \
        --rpc-url "$RPC_URL" --mpc-contract "$MPC_CONTRACT_ID" --nearblocks-url "$NEARBLOCKS_URL" 2>&1) || V4_REC_RC=$?
      echo "$V4_REC_OUT" >&2
      [[ $V4_REC_RC -eq 0 ]] || fail "V4d customer-recovery exited $V4_REC_RC"
      V4_MASTER=$(echo "$V4_REC_OUT" | awk -F= '/^master_hex=/{print $2; exit}')
      [[ -n "$V4_MASTER" && ${#V4_MASTER} -eq 64 ]] || fail "V4d no master_hex (got '${V4_MASTER:0:16}', len ${#V4_MASTER})"
      pass "V4d per-vault master recovered locally (64 hex chars)"
      # Fetch the encrypted ciphertext from the contract via get_secrets (accessor enum: {Project:{project_id}}).
      GET_ARGS=$(jq -nc --arg pid "$SECRET_PROJECT" --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" '{accessor:{Project:{project_id:$pid}}, profile:$profile, owner:$owner}')
      GET_ARGS_B64=$(printf '%s' "$GET_ARGS" | base64 | tr -d '\n')
      SECRETS_VIEW=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg a "$CONTRACT_ID" --arg ab "$GET_ARGS_B64" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:"get_secrets",args_base64:$ab}}')")
      ENCRYPTED_B64=$(echo "$SECRETS_VIEW" | jq -r '.result.result | implode' 2>/dev/null | jq -r '.encrypted_secrets // empty' 2>/dev/null)
      [[ -n "$ENCRYPTED_B64" && "$ENCRYPTED_B64" != "null" ]] || fail "V4d get_secrets returned no encrypted_secrets: $(echo "$SECRETS_VIEW" | head -c200)"
      pass "V4d fetched on-chain ciphertext (${#ENCRYPTED_B64} chars base64)"
      V4_DEC_RC=0
      V4_DECRYPTED=$("$RECOVERY_BIN" decrypt-secret --master "$V4_MASTER" --seed "$SECRET_SEED" --ciphertext-base64 "$ENCRYPTED_B64" 2>&1) || V4_DEC_RC=$?
      echo "V4d decrypt output: $V4_DECRYPTED" >&2
      [[ $V4_DEC_RC -eq 0 ]] || fail "V4d local decrypt failed (rc=$V4_DEC_RC) — derivation chain gap. keystore_pubkey=$KEYSTORE_PUBKEY master=$V4_MASTER seed=$SECRET_SEED"
      V4_DEC_VALUE=$(echo "$V4_DECRYPTED" | jq -r '.MY_TEST_SECRET // empty' 2>/dev/null || echo "")
      [[ "$V4_DEC_VALUE" == "$EXPECTED_SECRET_VALUE" ]] && pass "V4d local decryption matches: MY_TEST_SECRET='$V4_DEC_VALUE' — full sovereignty over secrets confirmed" \
        || fail "V4d decrypt mismatch: expected '$EXPECTED_SECRET_VALUE', got '$V4_DEC_VALUE'"
    fi
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# V5 — wk_-path sovereign exit  [VAULT/FUNDS] (funds + spends a throwaway wallet)
#       Ported from tests/sovereignty_e2e.sh — the /register(`wk_`) analog of V3. A THROWAWAY vault it
#       RETIRES. Full single-run flow (asserts the wallet-signing slice of the source — the keystore
#       transfer + project-secret legs are V4's job / covered by V3's derive path):
#         5a  POST /register {vault_id} mints a wk_ + wallet_id + near_account_id; PRE-RECOVERY
#             /sign-message returns a signature (keystore signs for this wallet);
#         5b  finalize_recovery flips vault.unlocked == true;
#         5c  POST-RECOVERY /sign-message must FAIL (vault unlocked → keystore refuses);
#         5d  recover master via MPC CKD; derive-wallet-key re-derives the SAME near_account_id the
#             keystore returned; then a REAL on-chain send-near signed by the locally-derived key LANDS
#             (final proof the customer independently controls the wallet).
#       NOTE: the source also drives a keystore-signed PRE-RECOVERY /wallet/v1/transfer + a project
#       secret /call (3b/3c/3d/8a/13/14). The transfer and the secrets dimension are V4's job /
#       require funded gas + a project; here V5 keeps the wallet-signing cutoff + the LOCAL-key
#       sovereign tx (the unique 'wk_ path' end-state). The wallet is funded (FUNDS) for 5d's tx.
# ════════════════════════════════════════════════════════════════════════════════
if want V5; then
  if [[ "$VAULT_MODE" == true ]]; then
    CUR_TEST="V5"
    log "V5 [VAULT/FUNDS] wk_-path sovereign exit — FULL single-run (register → 60s window → finalize → keystore refuses → MPC-CKD re-derive → REAL on-chain send-near by recovered key)"
    warn "V5 finalize_recovery is IRREVERSIBLE — it RETIRES this throwaway vault (unlocked, OutLayer-side TEE keys deleted). NEVER pointed at vault.\$PARENT (uses v5v.\$PARENT)."
    V5_VAULT=$(deploy_throwaway_vault "v5v$RUN_TAG") || fail "V5 deploy vault"
    if [[ -n "${V5_VAULT:-}" ]]; then
      THROWAWAY_VAULTS+=("$V5_VAULT")
      pass "V5 throwaway vault $V5_VAULT deployed"

      # 5a: mint wk_ bound to the vault + pre-recovery sign (the derive-sub-wallet work).
      REG=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d "$(jq -nc --arg v "$V5_VAULT" '{vault_id:$v}')")
      V5_WK=$(echo "$REG" | jq -r '.api_key // empty'); V5_WID=$(echo "$REG" | jq -r '.wallet_id // empty'); V5_ADDR=$(echo "$REG" | jq -r '.near_account_id // empty')
      [[ -n "$V5_WK" && "$V5_WK" != null && -n "$V5_WID" && -n "$V5_ADDR" && "$V5_ADDR" != null ]] || fail "V5a /register did not return api_key+wallet_id+near_account_id: $(echo "$REG" | head -c200)"
      pass "V5a minted wk_=${V5_WK:0:9}… wallet_id=$V5_WID address=$V5_ADDR"
      SR=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer $V5_WK" -H 'Content-Type: application/json' -d '{"message":"v5-preflight","recipient":"v5-verifier.testnet","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
      V5_PRESIG=$(echo "$SR" | jq -r '.signature // empty')
      [[ -n "$V5_PRESIG" && "$V5_PRESIG" != null ]] && pass "V5a PRE-RECOVERY keystore signed (sig len=${#V5_PRESIG})" || fail "V5a /sign-message returned no signature pre-recovery: $(echo "$SR" | head -c160)"

      # NOTE: funding is DEFERRED to 5d (just before the sovereign tx), NOT done up front. V5 dropped the
      # legacy keystore-signed pre-recovery /wallet/v1/transfer (that's what needed early gas), so the only
      # tx needing funds is 5d's LOCAL-key send — funding only after the derived key is in hand means an
      # early failure (before recovery) can never strand gas on an unrecoverable wallet.

      # 5b: 60s window (direct set_exit_window) → initiate → assert in-flight → wait window → finalize.
      # set_exit_window MUST precede initiate (finalize_after is frozen at initiate from the window).
      set_exit_window_60s "$V5_VAULT" "V5"
      log "V5 initiate unilateral recovery"
      vault_initiate_retry "$V5_VAULT" "V5"
      assert_recovery_in_flight "$V5_VAULT" "V5b"
      wait_finalizable "$V5_VAULT" "V5"
      V5_KEY=$("$RECOVERY_BIN" generate-key)
      V5_NEWPUB=$(echo "$V5_KEY" | jq -r '.public_key'); V5_NEWPRIV=$(echo "$V5_KEY" | jq -r '.private_key')
      [[ -n "$V5_NEWPUB" && -n "$V5_NEWPRIV" ]] || fail "V5 generate-key produced no keypair"
      finalize_and_assert_unlocked "$V5_VAULT" "$V5_NEWPUB" "V5b" || true

      # 5c: POST-RECOVERY /sign-message must FAIL (vault unlocked → keystore refuses to sign).
      PSR=$(curl -sS -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer $V5_WK" -H 'Content-Type: application/json' -d '{"message":"v5-postflight","recipient":"v5-verifier.testnet","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
      PSR_H=$(echo "$PSR" | tail -1 | sed 's/HTTP://'); PSR_B=$(echo "$PSR" | sed '$d')
      PSR_SIG=$(echo "$PSR_B" | jq -r '.signature // empty' 2>/dev/null || echo "")
      { [[ "$PSR_H" -ge 400 ]] || [[ -z "$PSR_SIG" || "$PSR_SIG" == "null" ]]; } && pass "V5c keystore refused signing post-recovery (HTTP $PSR_H) — sovereignty cutoff confirmed" \
        || fail "V5c POST-RECOVERY keystore STILL signed (HTTP $PSR_H sig=${PSR_SIG:0:20}) — cutoff broken"

      # 5d: MPC-CKD recover master → derive-wallet-key (uses the /register wallet_id directly) → assert the
      # derived near_address == the keystore's near_account_id → REAL send-near signed by the LOCAL key.
      log "V5d recover per-vault master via MPC CKD + re-derive wallet key + sovereign on-chain tx"
      V5_REC_RC=0
      V5_REC_OUT=$(VAULT_PRIVATE_KEY="$V5_NEWPRIV" "$RECOVERY_BIN" --vault-id "$V5_VAULT" --from-chain \
        --rpc-url "$RPC_URL" --mpc-contract "$MPC_CONTRACT_ID" --nearblocks-url "$NEARBLOCKS_URL" 2>&1) || V5_REC_RC=$?
      echo "$V5_REC_OUT" >&2
      [[ $V5_REC_RC -eq 0 ]] || fail "V5d customer-recovery exited $V5_REC_RC"
      V5_MASTER=$(echo "$V5_REC_OUT" | awk -F= '/^master_hex=/{print $2; exit}')
      [[ -n "$V5_MASTER" && ${#V5_MASTER} -eq 64 ]] || fail "V5d no master_hex (got '${V5_MASTER:0:16}', len ${#V5_MASTER})"
      pass "V5d per-vault master recovered locally (64 hex chars)"
      V5_DERIVED=$("$RECOVERY_BIN" derive-wallet-key --master "$V5_MASTER" --wallet-id "$V5_WID")
      V5_DER_ADDR=$(echo "$V5_DERIVED" | jq -r '.near_address'); V5_DER_PRIV=$(echo "$V5_DERIVED" | jq -r '.private_key')
      [[ "$V5_DER_ADDR" == "$V5_ADDR" ]] && pass "V5d local derivation matches keystore: $V5_DER_ADDR" \
        || fail "V5d DERIVATION MISMATCH: local=$V5_DER_ADDR vs keystore=$V5_ADDR"

      # 5d-fund: NOW the derived key is in hand — fund the wallet 0.05 NEAR so the sovereign tx has gas
      # (covers the 0.001 send + fees + the final delete-account reclaim). MONEY=true from here: a failure
      # mid-flight halts the suite, and the wallet is recoverable via the just-derived key ($V5_DER_PRIV).
      MONEY=true
      log "V5d fund the wallet ($V5_ADDR) with 0.05 NEAR from $PARENT (for the sovereign tx + reclaim)"
      fund_near "$V5_ADDR" "0.05 NEAR" || fail "V5d funding the wallet from $PARENT failed"
      for _ in 1 2 3 4 5 6 7 8; do
        if curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$V5_ADDR\"}}" | jq -e '.result.amount' >/dev/null 2>&1; then break; fi
        sleep 2
      done

      # The unique 'wk_ path' end-state: a REAL testnet tx, signed by the locally-derived key (no
      # outlayer vault send-near subcommand exists — use `near tokens send-near` via near_tty, exactly
      # like the legacy sovereignty_e2e.sh proof).
      log "V5d SOVEREIGN TX — locally-derived key signs send-near 0.001 NEAR → $PARENT"
      near_tty "near tokens \"$V5_ADDR\" send-near \"$PARENT\" '0.001 NEAR' network-config \"$NETWORK\" sign-with-plaintext-private-key '$V5_DER_PRIV' send" \
        || fail "V5d sovereign send-near with the locally-derived key failed — the wallet is NOT recoverable end-to-end"
      pass "V5d sovereign tx landed — wallet $V5_ADDR is controlled by the customer-held key, independent of OutLayer"

      # 5d-reclaim: drain the funded wallet back to BENEFICIARY with the RECOVERED key (leak-free cleanup;
      # also a second proof the local key has full authority). The keystore can't do this post-finalize.
      log "V5d reclaim — delete the funded wallet to $BENEFICIARY using the recovered key (no leak)"
      near_tty "near account delete-account \"$V5_ADDR\" beneficiary \"$BENEFICIARY\" network-config \"$NETWORK\" sign-with-plaintext-private-key '$V5_DER_PRIV' send" \
        || warn "V5d delete-account reclaim failed — $V5_ADDR may retain residual NEAR (recover via the recovered key)"
      MONEY=false; CUR_TEST=""
    fi
  else
    note "V5 SKIPPED (vault mode off): wk_-path sovereign exit requires a DEPLOYED vault to finalize_recovery on — set MPC_PUBLIC_KEY"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# V6 — a secret CREATED for an agent under a vault  [VAULT] (~0.32 NEAR, storage stake stays)
#       Where V4 reads a secret and proves the vault master stops decrypting after a sovereign
#       exit, V6 covers the other end: putting one there. Both money paths are exercised, because
#       both put a different account's NEAR at stake and only one of them is the ordinary case.
#
#       Asserts (over the shared VAULT_ID, project $CONNECTOR_PROJECT_ID):
#         6a  the encryption key is fetched under the agent's OWN auth and comes back naming that
#             agent and that project (seed == project:<project_id>:<agent>) — a key that named
#             anything else would seal the credential to somebody else's master;
#         6b  the same project under a vault-bound agent and under a default-master agent yields
#             DIFFERENT keys (both the wallet and the master differ — one scope cannot read the
#             other's secret);
#         6c  the agent's own wallet pays: `secrets set-for-agent --agent-pays` lands, the chain
#             reports the vault binding + an ECIES v1 blob under the agent's name, and what landed
#             is READABLE by that vault's master — nothing on the paying path checks, since the
#             keystore signs a transaction there rather than opening the bytes, so `/prepare` is
#             asked afterwards as an oracle (it refuses to sign what does not decrypt);
#         6d  an agent holding no NEAR is refused ACTIONABLY (a 4xx naming the amount and the
#             endpoint that pays for it) rather than failing somewhere downstream;
#         6e  a BLOCKCHAIN ACCOUNT pays for that same agent instead: `set-for-agent` prepares the
#             call, $PARENT sends `store_agent_secret`, and the secret lands under the AGENT's name
#             with the same vault binding while the agent's wallet still holds nothing;
#         6f  the signature covers what it claims: a third agent's secret is stored and its
#             ciphertext read back off the chain (`/prepare` will not sign bytes that do not
#             decrypt, so there is no made-up ciphertext to sign), then the vault, the audience,
#             the ciphertext, the name and the payer are each altered in turn on that otherwise
#             valid prepared call and the contract refuses all five — and the untouched call
#             lands, so the refusals are the tampering and not the setup.
#
#       COSTS: three storage deposits of 0.1 NEAR (6c, 6e, 6f) plus 0.3 NEAR funding one agent
#       wallet. The deposits are refundable only by `delete_secrets` from the OWNER — the agent's
#       wallet — so this suite does not reclaim them.
#
#       Needs the `set-for-agent` subcommand ($OUTLAYER_BIN, default `outlayer`). An older binary
#       SKIP-notes rather than failing: it is a missing tool, not a broken guarantee.
# ════════════════════════════════════════════════════════════════════════════════
if want V6 && agent_secret_mode V6; then
  if [[ "$VAULT_MODE" != true ]]; then
    note "V6 SKIPPED (vault mode off): a secret can only be BOUND to a vault that exists — set MPC_PUBLIC_KEY"
  elif ! "$OUTLAYER_BIN" secrets set-for-agent --help >/dev/null 2>&1; then
    note "V6 SKIPPED: '$OUTLAYER_BIN secrets set-for-agent' is not available. Build and install outlayer-cli, or point OUTLAYER_BIN at the built binary."
  elif [[ -z "$CONNECTOR_PROJECT_ID" ]]; then
    note "V6 SKIPPED: CONNECTOR_PROJECT_ID is empty. It must name a project that EXISTS on chain — the contract refuses a secret for one that does not."
  else
    log "V6 [VAULT] a secret created for an agent under $VAULT_ID (project $CONNECTOR_PROJECT_ID)"

    # ── 6a: the key, fetched under the agent's own authentication ──────────────
    V6_REG=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg v "$VAULT_ID" '{vault_id:$v}')")
    V6_WK=$(echo "$V6_REG" | jq -r '.api_key // empty')
    V6_AGENT=$(echo "$V6_REG" | jq -r '.near_account_id // empty')
    if [[ "$V6_WK" != wk_* || -z "$V6_AGENT" ]]; then
      fail "V6a /register under $VAULT_ID returned no wk_ + account: $(echo "$V6_REG" | head -c200)"
    else
      note "V6 agent A: $V6_AGENT"
      V6_PUB=$(agent_secret_pubkey "$V6_WK" "$CONNECTOR_PROJECT_ID")
      V6_KEY=$(echo "$V6_PUB" | jq -r '.pubkey // empty')
      V6_SEED=$(echo "$V6_PUB" | jq -r '.seed // empty')
      V6_NAMED=$(echo "$V6_PUB" | jq -r '.agent_account // empty')
      V6_WANT_SEED="project:$CONNECTOR_PROJECT_ID:$V6_AGENT"
      if [[ "$V6_SEED" == "$V6_WANT_SEED" && "$V6_NAMED" == "$V6_AGENT" && ${#V6_KEY} -eq 64 ]]; then
        pass "V6a the key names this agent and this project (seed=$V6_SEED)"
      else
        fail "V6a the key came back for something else: seed='$V6_SEED' (wanted '$V6_WANT_SEED'), agent='$V6_NAMED', key length ${#V6_KEY}"
      fi

      # ── 6b: a different scope is a different key ────────────────────────────
      V6_DREG=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}')
      V6_DWK=$(echo "$V6_DREG" | jq -r '.api_key // empty')
      V6_DKEY=$(agent_secret_pubkey "$V6_DWK" "$CONNECTOR_PROJECT_ID" | jq -r '.pubkey // empty')
      if [[ -z "$V6_DKEY" ]]; then
        fail "V6b the default-master agent returned no key: $(echo "$V6_DREG" | head -c160)"
      elif [[ "$V6_DKEY" != "$V6_KEY" ]]; then
        pass "V6b the vault-bound agent and the default-master agent get different keys"
      else
        fail "V6b BOTH scopes returned the SAME key $V6_KEY — a secret sealed under one would be readable under the other"
      fi

      # ── 6c: the agent's own wallet pays ────────────────────────────────────
      # MONEY stays false throughout V6: it marks funds in flight that the EXIT
      # trap can still sweep, and nothing V6 spends is sweepable — the deposits
      # belong to the agents and the header says so. A halt here would abandon
      # the remaining assertions without saving anything.
      # 0.3 NEAR, not the 0.11 the coordinator's pre-flight asks for. That floor
      # covers the 0.1 deposit plus a gas allowance, and testnet then refuses the
      # broadcast anyway — the chain quoted 0.2 NEAR for the same call. Funding
      # to the pre-flight minimum tests the edge rather than the path.
      log "V6c fund agent A with 0.3 NEAR and let it pay for its own secret"
      fund_fresh "$V6_AGENT" "0.3 NEAR" || fail "V6c funding agent A failed"
      if store_agent_secret_cli "$V6_WK" \
           "$(jq -nc --arg v "v6c-$RUN_TAG" '{V6_AGENT_PAYS:$v}')" \
           --vault-id "$VAULT_ID" --agent-pays; then
        assert_agent_secret "V6c" "$V6_AGENT"

        # Is what landed actually READABLE by the vault's master? Nothing on
        # this path checks: the keystore signs a transaction rather than a
        # message, so it never opens the bytes, and a secret sealed to the
        # wrong master would land looking perfectly correct and fail months
        # later at the only moment it is needed.
        #
        # `/prepare` is the oracle. It refuses to sign anything that does not
        # decrypt under the agent's seed, so feeding it what is already on
        # chain asks exactly the question — and asking costs nothing, because
        # the prepared call is never sent.
        V6_STORED_CT=$(agent_secret_view "$V6_AGENT" | jq -r '.profile.encrypted_secrets // empty')
        V6_READABLE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
          "$COORDINATOR_URL/wallet/v1/agent-secret/prepare" \
          -H "Authorization: Bearer $V6_WK" -H 'Content-Type: application/json' \
          -d "$(jq -nc --arg p "$CONNECTOR_PROJECT_ID" --arg c "$V6_STORED_CT" --arg payer "$PARENT" \
                '{project_id:$p, encrypted_secrets_base64:$c, payer:$payer}')")
        if [[ "$V6_READABLE" == 2?? ]]; then
          pass "V6c what landed decrypts under $VAULT_ID's master — the keystore signed for it"
        else
          fail "V6c the stored secret does NOT decrypt under $VAULT_ID's master (prepare answered $V6_READABLE) — it was sealed to the wrong key and nothing on the paying path would have noticed"
        fi
      else
        fail "V6c set-for-agent --agent-pays did not store the secret"
      fi

      # ── 6d / 6e: an agent with nothing, paid for by a blockchain account ────
      V6_REG_B=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg v "$VAULT_ID" '{vault_id:$v}')")
      V6_WK_B=$(echo "$V6_REG_B" | jq -r '.api_key // empty')
      V6_AGENT_B=$(echo "$V6_REG_B" | jq -r '.near_account_id // empty')
      if [[ "$V6_WK_B" != wk_* || -z "$V6_AGENT_B" ]]; then
        fail "V6d /register (agent B) returned no wk_ + account: $(echo "$V6_REG_B" | head -c200)"
      else
        note "V6 agent B (unfunded): $V6_AGENT_B"
        V6_DENIED=$(OUTLAYER_WALLET_KEY="$V6_WK_B" "$OUTLAYER_BIN" secrets set-for-agent \
          "$(jq -nc '{V6_NEVER_STORED:"x"}')" \
          --project "$CONNECTOR_PROJECT_ID" --agent-pays 2>&1) && V6_DENIED_RC=0 || V6_DENIED_RC=$?
        if [[ ${V6_DENIED_RC:-0} -eq 0 ]]; then
          fail "V6d an agent holding no NEAR stored a secret it cannot have paid for"
        elif echo "$V6_DENIED" | grep -q "prepare"; then
          pass "V6d an unfunded agent is refused, and told which endpoint pays instead"
        else
          fail "V6d the refusal does not say how to proceed: $(echo "$V6_DENIED" | tail -c300)"
        fi

        log "V6e $PARENT pays for agent B's secret (store_agent_secret)"
        if store_agent_secret_cli "$V6_WK_B" \
             "$(jq -nc --arg v "v6e-$RUN_TAG" '{V6_PAYER_PAYS:$v}')" \
             --vault-id "$VAULT_ID"; then
          assert_agent_secret "V6e" "$V6_AGENT_B"
          # The point of the payer path: the agent still needs no NEAR of its own.
          V6_BAL=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$V6_AGENT_B\"}}" \
            | jq -r '.result.amount // "0"')
          [[ "$V6_BAL" == "0" ]] && pass "V6e agent B still holds no NEAR — the payer carried the whole cost" \
            || note "V6e agent B holds $V6_BAL yoctoNEAR (it was funded outside this run)"
        else
          fail "V6e set-for-agent (payer path) did not store the secret"
        fi
      fi

      # ── 6f: what the signature covers ──────────────────────────────────────
      # Driven through the endpoint rather than the CLI: the CLI refuses an
      # altered call before it is ever sent (that is its job, and its own tests
      # cover it), and what is under test here is the CONTRACT's refusal.
      #
      # Agent C's secret is stored FIRST, through the CLI, and the ciphertext is
      # then read back off the chain. `/prepare` will not sign bytes that do not
      # decrypt under the agent's seed, so made-up ciphertext never gets as far
      # as a signature — and a signature is precisely what has to exist before
      # it can be shown not to cover something. Re-sending the untouched call at
      # the end updates that same secret, so the storage is staked once.
      V6_REG_C=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg v "$VAULT_ID" '{vault_id:$v}')")
      V6_WK_C=$(echo "$V6_REG_C" | jq -r '.api_key // empty')
      V6_AGENT_C=$(echo "$V6_REG_C" | jq -r '.near_account_id // empty')
      if [[ "$V6_WK_C" != wk_* ]]; then
        fail "V6f /register (agent C) returned no wk_: $(echo "$V6_REG_C" | head -c200)"
      elif ! store_agent_secret_cli "$V6_WK_C" \
             "$(jq -nc --arg v "v6f-$RUN_TAG" '{V6_SIGNED_OVER:$v}')" \
             --vault-id "$VAULT_ID"; then
        fail "V6f could not store agent C's secret to tamper with"
      else
        note "V6 agent C: $V6_AGENT_C"
        V6_CT=$(agent_secret_view "$V6_AGENT_C" | jq -r '.profile.encrypted_secrets // empty')
        V6_PREP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/agent-secret/prepare" \
          -H "Authorization: Bearer $V6_WK_C" -H 'Content-Type: application/json' \
          -d "$(jq -nc --arg p "$CONNECTOR_PROJECT_ID" --arg c "$V6_CT" --arg payer "$PARENT" \
                '{project_id:$p, encrypted_secrets_base64:$c, payer:$payer}')")
        V6_ARGS=$(echo "$V6_PREP" | jq -c '.args // empty')
        if [[ -z "$V6_CT" ]]; then
          fail "V6f agent C's ciphertext is not on chain — nothing to re-sign"
        elif [[ -z "$V6_ARGS" ]]; then
          fail "V6f /agent-secret/prepare returned no call: $(echo "$V6_PREP" | head -c200)"
        else
          # Each entry alters ONE field the signed message covers. All must be refused.
          V6_TAMPERED=()
          V6_TAMPERED+=("the vault|$(echo "$V6_ARGS" | jq -c '.vault_id = null')")
          V6_TAMPERED+=("the audience|$(echo "$V6_ARGS" | jq -c --arg p "$PARENT" '.access = {Whitelist:[$p]}')")
          V6_TAMPERED+=("the ciphertext|$(echo "$V6_ARGS" | jq -c '.encrypted_secrets_base64 = "dGFtcGVyZWQ="')")
          V6_TAMPERED+=("the name|$(echo "$V6_ARGS" | jq -c --arg a "$V6_AGENT" '.profile = $a')")

          for entry in "${V6_TAMPERED[@]}"; do
            what=${entry%%|*}; args=${entry#*|}
            if store_agent_secret_as_parent "$args"; then
              fail "V6f the contract ACCEPTED a call with $what altered — the signature does not cover it"
            else
              pass "V6f altering $what is refused by the contract"
            fi
          done

          # A call prepared for a DIFFERENT payer, sent by $PARENT. Nothing is
          # altered afterwards: the signature simply names someone else.
          #
          # The name is derived from $PARENT so it CANNOT be $PARENT — $BENEFICIARY
          # and $APPROVER1 both default to the same account on testnet, and a test
          # that prepares a call for the very account that sends it proves nothing
          # while looking like it does. It need not exist: `/prepare` only puts the
          # name in the signature, and the contract compares against whoever sent
          # the transaction.
          V6_OTHER_PAYER="not-the-payer.$PARENT"
          V6_OTHER=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/agent-secret/prepare" \
            -H "Authorization: Bearer $V6_WK_C" -H 'Content-Type: application/json' \
            -d "$(jq -nc --arg p "$CONNECTOR_PROJECT_ID" --arg c "$V6_CT" --arg payer "$V6_OTHER_PAYER" \
                  '{project_id:$p, encrypted_secrets_base64:$c, payer:$payer}')" | jq -c '.args // empty')
          if [[ -z "$V6_OTHER" ]]; then
            fail "V6f the prepare-for-another-payer call returned nothing"
          elif store_agent_secret_as_parent "$V6_OTHER"; then
            fail "V6f $PARENT sent a call prepared for $V6_OTHER_PAYER and the contract took it — the payer is not bound"
          else
            pass "V6f a call prepared for another payer is refused when $PARENT sends it"
          fi

          # Positive control, last: the untouched call must land, or every
          # refusal above proves only that the setup was broken.
          if store_agent_secret_as_parent "$V6_ARGS"; then
            pass "V6f the untouched prepared call lands — the refusals above were the tampering"
            assert_agent_secret "V6f" "$V6_AGENT_C"
          else
            fail "V6f the UNTOUCHED prepared call was refused — the five refusals above prove nothing"
          fi
        fi
      fi
    fi
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# Final fund-return + leak check. The final sweep_now catches any TRAILING wallets left by
# non-money tests (which don't call return_test_funds); verify_all_drained then re-reads EVERY
# sub-wallet ever created. MONEY=false here so a leak fail() RECORDS (not aborts) and surfaces in
# the SUMMARY exit code below, rather than fail-fast halting before the summary prints.
MONEY=false; sweep_now; verify_all_drained

echo
log "SUMMARY"
pass "passed: $PASS"
if [[ $FAILED -gt 0 ]]; then
  for n in "${FAILED_NAMES[@]}"; do printf '\033[31m  ✗ %s\033[0m\n' "$n" >&2; done
  fail "FAILED: $FAILED"; exit 1
fi
pass "ALL UNIFIED-VAULT E2E CHECKS PASSED"
# Vault-lifecycle costs are DISTINCT from the sub-wallet sweep and are NOT auto-returned by this suite.
if [[ ${#THROWAWAY_VAULTS[@]} -gt 0 ]]; then
  warn "VAULTS TOUCHED THIS RUN (${#THROWAWAY_VAULTS[@]}) — reused if already on chain (no new stake) or first-deployed (~0.1 NEAR"
  warn "       LOCKED storage stake the sub-wallet sweep does NOT reclaim):"
  for v in "${THROWAWAY_VAULTS[@]}"; do warn "         - $v"; done
  if [[ ${#RETIRED_VAULTS[@]} -gt 0 ]]; then
    warn "RETIRED THIS RUN (${#RETIRED_VAULTS[@]}) — V3/V4/V5 called finalize_recovery: these are IRREVERSIBLY unlocked (OutLayer-side TEE keys"
    warn "       deleted, the customer's generated key is now the sole FullAccess key). They are NO LONGER usable by OutLayer — do NOT reuse:"
    for v in "${RETIRED_VAULTS[@]}"; do warn "         - $v (RETIRED)"; done
    warn "       The ~0.1 NEAR stake on each remains LOCKED until the customer (now sole key-holder) deletes the vault account themselves."
  fi
  warn "The SHARED/V1 vaults (vault.\$PARENT, vaultb.\$PARENT) were NOT finalized → SAFE TO REUSE. A V3/V4/V5 re-run deploys a FRESH throwaway"
  warn "       vault automatically only if the prior one was deleted; a still-on-chain retired (unlocked) vault would be REUSED-then-rejected at"
  warn "       initiate (it's already unlocked), so let the operator delete retired vaults between full --apply runs if re-running V3/V4/V5."
elif [[ -n "$VAULT_ID" ]]; then
  warn "Cleanup (optional): $VAULT_ID holds locked NEAR + per-wallet policy storage stakes (vault stake NOT auto-returned)."
fi
