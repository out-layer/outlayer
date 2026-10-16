#!/usr/bin/env bash
#
# Every custody suite, in one run.
#
# `run_all.sh` deliberately does not carry these: it is the build-and-compile
# gate, it must stay fast and free, and these spend real testnet NEAR, need a
# database wrapper, and take the better part of an hour. But left out of any
# runner at all they were the best tests in the repo and nothing ran them —
# which is how a suite ends up not executable, or unable to fail, without
# anyone noticing.
#
# WHAT IT DOES ABOUT THE THINGS THAT BITE:
#
#   Rate limit. The coordinator allows 100 requests/minute per IP, and over it
#   answers with resets and `HTTP 000` that read like product failures — one
#   evening of this session went to diagnosing it. Suites run STRICTLY
#   sequentially with a gap between them ($GAP, default 75s).
#
#   Network. `outlayer` follows ~/.outlayer/default-network unless told
#   otherwise, which on this machine is MAINNET. Exported once, here.
#
#   The binding. Three suites need an ACTIVE personal_account binding, and
#   minting one costs an account plus NEAR. This runner mints ONE with
#   binding_lifecycle (KEEP=1) and hands it to the rest, or takes yours.
#
#   Prerequisites. A suite whose inputs are missing is SKIPPED loudly, naming
#   exactly what is absent. It is never counted as a pass.
#
# Usage:
#   ./tests/run_custody.sh                       # print the plan, run nothing
#   PARENT=you.testnet PSQL_CMD=./tsql \
#     ./tests/run_custody.sh --apply             # everything it has inputs for
#   PARENT=you.testnet ./tests/run_custody.sh --apply velocity binding
#                                                # only the named suites
#
# Inputs (each suite states its own; supply what you have):
#   PARENT           a testnet account with a keychain credential and ~5 NEAR
#   PSQL_CMD         wrapper taking one SQL statement — the coordinator's
#                    database is not reachable off its host
#   FUNDER EXECUTOR RECIPIENT   three accounts, for the contract-level probes
#   MPC_PUBLIC_KEY   enables the dedicated-vault probes; without it the vault
#                    suite runs in default-vault mode
#   API_KEY APPROVER ADMIN_TOKEN BOUND_TO   per-suite extras

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
ARGS=()
for a in "$@"; do
  case "$a" in
    --apply) APPLY=true ;;
    -h|--help) sed -n '3,44p' "$0"; exit 0 ;;
    *) ARGS+=("$a") ;;
  esac
done

# BOTH, and NETWORK first: `wallet_confidential_e2e.sh` and
# `unified_op_e2e_intents.sh` default `NETWORK` to **mainnet**, and the latter
# then re-exports OUTLAYER_NETWORK from it — so exporting only OUTLAYER_NETWORK
# leaves them pointed at mainnet inside a run whose banner says testnet.
export NETWORK="${NETWORK:-testnet}"
export OUTLAYER_NETWORK="${OUTLAYER_NETWORK:-$NETWORK}"
GAP="${GAP:-75}"

# `gtimeout` on macOS with coreutils, `timeout` on Linux, nothing otherwise.
if command -v timeout >/dev/null 2>&1;      then TIMEOUT="timeout --foreground ${SUITE_TIMEOUT:-1800}"
elif command -v gtimeout >/dev/null 2>&1;   then TIMEOUT="gtimeout --foreground ${SUITE_TIMEOUT:-1800}"
else TIMEOUT=""; fi

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }

RAN=(); PASSED=(); FAILED=(); SKIPPED=()

# name | script | required env vars (space separated) | what it covers
SUITES=(
  "binding|binding_lifecycle_e2e.sh|PARENT|the binding state machine: PUT/GET/DELETE, the setup kit, and the refusal messages for each wrong shape"
  "personal-wallet|personal_wallet_e2e.sh|FUNDER EXECUTOR RECIPIENT|the installed wallet contract itself: the kit transaction, the code hash, membership, the fund lane, and four distinct contract-level refusals"
  "personal-global|personal_wallet_global_e2e.sh|FUNDER EXECUTOR RECIPIENT|the same install by GLOBAL contract reference (NEP-591) rather than by uploaded bytes"
  "velocity|velocity_accounting_e2e.sh|PARENT PSQL_CMD|what the velocity counters are actually fed — refused calls, partial promises, gross deposits, the calendar buckets"
  "concurrent|wallet_concurrent_spend_e2e.sh|PARENT|two spends at the same instant against one ceiling — the only suite that fires simultaneous requests"
  "credentials|call_credentials_e2e.sh|PARENT|which credential may pay for a /call and which may not"
  "probe|wallet_probe_e2e.sh|PARENT RECIPIENT OUTSIDER|the wallet surface end to end on a self-minted wallet"
  "bound-identity|bound_identity_onchain_e2e.sh|PARENT BINDING_SEED ASSET|use_bound_identity over the ON-CHAIN door, and that billing does not follow the borrowed name"
  "identity-https|hos_identity_e2e.sh|PARENT|the HTTPS half of use_bound_identity: unbound, pending, and a key that names no wallet are refused rather than answered with the caller's own name"
  "stuck-repair|stuck_request_repair_e2e.sh|PARENT PSQL_CMD|the lazy repair of rows left in processing, including the door's per-promise detail"
  "approvals|approval_flow_wk_e2e.sh|PARENT APPROVER|multisig approval over a wk_ credential"
  "refusals|refusals_e2e.sh|PARENT|the endpoints that exist to say no: /reject's signature binding, the internal endpoints' auth gate, and delete toward an address the policy does not list"
  "policy-sync|internal_policy_sync_e2e.sh|PARENT PSQL_CMD|the indexer policy sync through the TEE worker, for Bearer near: and wk_ vault wallets"
  "unified-op|unified_op_e2e.sh|PARENT|the canonical-op surface: auth-sign, approve/reject, sign_message, delete, negatives"
  "unified-intents|unified_op_e2e_intents.sh|PARENT|the intents half of the same surface"
  "unified-vault|unified_vault_e2e.sh|PARENT|vault isolation and the sovereign exit — V1 is the real multi-customer isolation test"
  "vault-recovery|vault_recovery_e2e.sh|PARENT|recovery procedures"
  "pricing|connector_pricing_e2e.sh|CALLER|connector prices on chain and the coordinator's cache"
)

missing_for() { # missing_for "VAR1 VAR2" → prints the ones that are unset/empty
  local out=()
  for v in $1; do [[ -n "${!v:-}" ]] || out+=("$v"); done
  # `:-` because `set -u` treats an empty array as unbound — which is the
  # common case here, and without it every satisfied suite printed an error.
  echo "${out[*]:-}"
}

wanted() { # wanted <name> — no filter means everything
  (( ${#ARGS[@]} == 0 )) && return 0
  for a in "${ARGS[@]}"; do [[ "$a" == "$1" ]] && return 0; done
  return 1
}

# ── the plan ─────────────────────────────────────────────────────────────────
if [[ "$APPLY" != true ]]; then
  sed -n '3,44p' "$0" >&2
  log "Plan on this machine"
  for entry in "${SUITES[@]}"; do
    IFS='|' read -r name script req what <<<"$entry"
    wanted "$name" || continue
    miss=$(missing_for "$req")
    if [[ -n "$miss" ]]; then
      printf '  \033[33m☐ %-16s SKIP — needs %s\033[0m\n' "$name" "$miss" >&2
    else
      printf '  \033[32m☑ %-16s %s\033[0m\n' "$name" "$script" >&2
    fi
  done
  echo >&2
  if [[ -z "${BINDING_SEED:-}" || -z "${ASSET:-}" ]]; then
    note "BINDING_SEED/ASSET are unset: --apply mints one binding first and hands it to the suites above that ask for it, so they will run rather than skip."
  fi
  [[ -z "$TIMEOUT" ]] && note "No timeout(1) here — a wedged suite will hold the run. Install coreutils for a watchdog."
  note "Pass --apply to run. Expect roughly an hour with the ${GAP}s gaps, and real testnet NEAR to move."
  exit 0
fi

[[ -n "${PARENT:-}" ]] || { echo "✗ PARENT is required for every suite here" >&2; exit 1; }

# A mistyped suite name selected nothing and exited 0 with "0 passed, 0 failed,
# 0 skipped", which reads like a clean run.
for a in "${ARGS[@]:-}"; do
  [[ -z "$a" ]] && continue
  known=false
  for e in "${SUITES[@]}"; do IFS='|' read -r n _ _ _ <<<"$e"; [[ "$a" == "$n" ]] && known=true; done
  $known || { echo "✗ no suite called '$a'. Run with no arguments to see the list." >&2; exit 1; }
done

# ── one binding, shared ──────────────────────────────────────────────────────
# Minting it costs an account and NEAR, and three suites want the same one.
if [[ -z "${BINDING_SEED:-}" || -z "${ASSET:-}" ]] \
   && { wanted bound-identity || wanted velocity || wanted stuck-repair; }; then
  log "Minting one binding for the suites that need it (KEEP=1)"
  BL=$(mktemp -t custody_bind.XXXXXX)
  if KEEP=1 "$SCRIPT_DIR/binding_lifecycle_e2e.sh" --apply 2>&1 | tee "$BL" >&2; then
    # STRIP THE COLOURS FIRST. The line is printed through `note`, which wraps it
    # in an ANSI reset, and `[^ ]*` stops at a space — which `\033[0m` is not. So
    # the LAST value on the line came out with the escape glued to it, and only
    # that one: `ASSET` survived because something follows it. A seed carrying a
    # reset is refused by `/wallet/v1/address` ("only [a-zA-Z0-9._-] allowed"),
    # which reads as a broken endpoint rather than a mangled argument.
    BL_PLAIN=$(sed $'s/\033\[[0-9;]*[mK]//g' "$BL")
    BINDING_SEED=$(grep -o 'BINDING_SEED=[^ ]*' <<<"$BL_PLAIN" | tail -1 | cut -d= -f2)
    ASSET=$(grep -o 'ASSET=[^ ]*' <<<"$BL_PLAIN" | tail -1 | cut -d= -f2)
    export BINDING_SEED ASSET
    # `stuck_request_repair_e2e.sh` reads REUSE_SEED/BOUND_TO, not
    # BINDING_SEED/ASSET — without these its R4 door probe silently skips, and
    # R4 is the only place the repair's per-promise decoding is exercised.
    export REUSE_SEED="$BINDING_SEED" BOUND_TO="$PARENT"
    [[ -n "$BINDING_SEED" && -n "$ASSET" ]] \
      && note "binding: $ASSET (seed $BINDING_SEED) — reuse it with BINDING_SEED=… ASSET=…" \
      || warn "binding_lifecycle printed no seed/asset; the suites needing one will skip"
  else
    warn "binding_lifecycle failed — the suites needing a binding will skip"
  fi
  rm -f "$BL"
  # It already ran; do not run it twice. An empty result here would re-enable
  # EVERYTHING (`wanted` is true for all when the filter is empty), so the
  # marker suite is used to keep the list non-empty.
  ARGS=($(for e in "${SUITES[@]}"; do IFS='|' read -r n _ _ _ <<<"$e"; wanted "$n" && [[ "$n" != binding ]] && echo "$n"; done))
  ARGS=("${ARGS[@]:-__none__}")
  if [[ -n "$BINDING_SEED" && -n "$ASSET" ]]; then
    PASSED+=("binding (as part of setup)")
  else
    FAILED+=("binding (setup mint failed)")
  fi
fi

# ── run ──────────────────────────────────────────────────────────────────────
FIRST=true
for entry in "${SUITES[@]}"; do
  IFS='|' read -r name script req what <<<"$entry"
  wanted "$name" || continue
  miss=$(missing_for "$req")
  if [[ -n "$miss" ]]; then
    warn "SKIP $name — needs $miss"
    SKIPPED+=("$name (needs $miss)")
    continue
  fi
  if [[ ! -x "$SCRIPT_DIR/$script" ]]; then
    warn "SKIP $name — $script is not executable"
    SKIPPED+=("$name (not executable)")
    continue
  fi
  # The gap goes BEFORE each suite but the first: back to back, the second one
  # starts inside the first one's rate-limit window and fails as the product.
  if [[ "$FIRST" != true ]]; then
    note "waiting ${GAP}s for the rate-limit window"
    sleep "$GAP"
  fi
  FIRST=false
  log "$name — $what"
  RAN+=("$name")
  # Several suites poll on-chain state in loops; one that wedges would hold the
  # whole run with no output and no way to tell it from slow. macOS has no
  # `timeout` unless coreutils is installed, so this is best-effort rather than
  # a requirement — refusing to run for want of a watchdog would be worse than
  # running without one.
  if $TIMEOUT "$SCRIPT_DIR/$script" --apply; then
    PASSED+=("$name")
  else
    rc=$?
    # 3 = the suite ran and asserted nothing, because its subject is not
    # reachable from here (intents on testnet, a credential this machine does
    # not hold). That is this runner's definition of a skip, and the whole
    # point of the skip column is that it is not a pass — a suite reporting
    # zero checks under a green tick is exactly what it was written to prevent.
    if (( rc == 3 )); then
      warn "SKIP $name — it ran but had nothing to check; see its own output above"
      SKIPPED+=("$name (nothing to check here)")
    else
      FAILED+=("$name")
      (( rc == 124 )) \
        && warn "$name TIMED OUT after ${SUITE_TIMEOUT:-1800}s — continuing" \
        || warn "$name FAILED ($rc) — continuing; the rest are independent"
    fi
  fi
done

# ── verdict ──────────────────────────────────────────────────────────────────
log "custody suites — ${#PASSED[@]} passed, ${#FAILED[@]} failed, ${#SKIPPED[@]} skipped"
for n in "${PASSED[@]:-}";  do [[ -n "$n" ]] && printf '  \033[32m✓ %s\033[0m\n' "$n" >&2; done
for n in "${SKIPPED[@]:-}"; do [[ -n "$n" ]] && printf '  \033[33m☐ %s\033[0m\n' "$n" >&2; done
for n in "${FAILED[@]:-}";  do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
(( ${#SKIPPED[@]} > 0 )) && note "a skip is not a pass — supply the inputs above to close the gap"
(( ${#FAILED[@]} > 0 )) && exit 1
exit 0
