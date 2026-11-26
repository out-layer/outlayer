#!/usr/bin/env bash
#
# Runs every HoS Agent Connect suite, in order, and prints the coverage the
# partner asked to see: endpoint × class, and acceptance R0–R11 with an honest
# label on each — `live`, `stub`, or `waits-TLA`.
#
# SEQUENTIALLY, always. The wallet routes allow 100 requests a minute per IP
# and the limiter lives in the coordinator's memory, so two suites in parallel
# produce 429s and connection resets that are indistinguishable from defects.
# Half of every previous full run's "failures" were this.
#
#   PARENT=you.testnet ./tests/run_hos_suite.sh --apply
#   PARENT=you.testnet ONLY="decoder custody" ./tests/run_hos_suite.sh --apply
#
# Export PSQL_CMD as well to get §I6/§I7 — attribution and the R8 audit trail.
# They read the coordinator's own rows, which is the only place the question
# "who is billed for this, and what happened to it" has an answer; without the
# variable both sections step aside loudly. See .idea/TESTING-WITH-ADMIN.md.
#
# Exits non-zero if any suite failed. A suite that RAN and judged nothing exits 3
# and is reported as NOTHING — never as ok, because the run is silent about what
# it covers rather than green on it.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "${1:-}" == "--apply" ]] || { sed -n '3,22p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
: "${PARENT:?USAGE: PARENT=you.testnet $0 --apply}"
export OUTLAYER_NETWORK="${NETWORK:-testnet}"
LOGDIR="${LOGDIR:-/tmp/hos-suite-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$LOGDIR"

log()  { printf '\n\033[1;36m════ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }

SUITES=(
  "endpoints|hos_endpoints_e2e.sh|§2 every endpoint of the method list, by class"
  "decoder|hos_decoder_policy_e2e.sh|§3 the decoder and the mode-blind core policy"
  "lease|hos_lease_stub_e2e.sh|§3.1 the hos_lease profile, through the §10 stub"
  "custody|hos_custody_matrix_e2e.sh|§4 limits, rights, capabilities, multisig, freeze"
  "secrets|secret_access_conditions_e2e.sh|§4.1 + S7 the AccessCondition gates, on a real WASI run"
  "gas|hos_gas_floor_e2e.sh|§R6 the executor's gas floor, warning and terminal refusal"
  "identity|hos_identity_e2e.sh|§5 use_bound_identity and attribution"
  "lifecycle|hos_lifecycle_e2e.sh|§6 lifecycle and invalidation (R5)"
  "dos|hos_dos_e2e.sh|§7 resource abuse"
)
ONLY="${ONLY:-}"

# A FRESH shared fixture every full run. A wallet carries a daily custody
# allowance of 100 operations, and a re-used fixture arrives with an unknown
# share of it already spent — after which suites fail on the cap and the failure
# reads as a policy defect. The suites that spend most of an allowance on their
# own (decoder, custody, lease, lifecycle, identity) build their own wallets;
# this one carries the two that do not.
log "Building a fresh shared fixture"
bash "$SCRIPT_DIR/hos_fixture.sh" --destroy >/dev/null 2>&1 || true
bash "$SCRIPT_DIR/hos_fixture.sh" --apply 2>&1 | tee "$LOGDIR/fixture.log" >&2 || {
  echo "the fixture could not be built — nothing below would be judgeable" >&2; exit 1; }

declare -a RESULTS=()
FAILED_SUITES=0
# Suites that ran and judged nothing (exit 3 — see `verdict` in lib/hos_common.sh).
# Counted apart from failures and apart from passes: their subject was not
# reachable from here, so the run says nothing about it either way.
NOTHING_SUITES=0
for entry in "${SUITES[@]}"; do
  name=${entry%%|*}; rest=${entry#*|}; script=${rest%%|*}; desc=${rest#*|}
  if [[ -n "$ONLY" && " $ONLY " != *" $name "* ]]; then
    RESULTS+=("$name|skipped|-|-|-|$desc"); continue
  fi
  log "$name — $desc"
  bash "$SCRIPT_DIR/$script" --apply > "$LOGDIR/$name.log" 2>&1
  rc=$?
  line=$(grep -oE "— [0-9]+ passed, [0-9]+ failed, [0-9]+ skipped, [0-9]+ finding" "$LOGDIR/$name.log" | tail -1)
  p=$(grep -oE "[0-9]+ passed" <<<"$line" | grep -oE "[0-9]+")
  f=$(grep -oE "[0-9]+ failed" <<<"$line" | grep -oE "[0-9]+")
  s=$(grep -oE "[0-9]+ skipped" <<<"$line" | grep -oE "[0-9]+")
  g=$(grep -oE "[0-9]+ finding" <<<"$line" | grep -oE "[0-9]+")
  case $rc in
    0) st=ok ;;
    3) st=NOTHING; NOTHING_SUITES=$((NOTHING_SUITES+1)) ;;
    *) st=FAILED; FAILED_SUITES=$((FAILED_SUITES+1)) ;;
  esac
  RESULTS+=("$name|$st|${p:-?}|${f:-?}|${s:-0}/${g:-0}|$desc")
  tail -25 "$LOGDIR/$name.log" >&2
  note "full log: $LOGDIR/$name.log"
  # The per-IP window is a minute wide; a gap between suites costs a minute and
  # buys back a whole class of phantom failures.
  sleep 45
done

log "Suite results"
printf '  %-10s %-8s %6s %6s %8s  %s\n' SUITE STATUS PASS FAIL SKIP/FIND DESCRIPTION >&2
for r in "${RESULTS[@]}"; do
  IFS='|' read -r n st p f sg d <<<"$r"
  printf '  %-10s %-8s %6s %6s %8s  %s\n' "$n" "$st" "$p" "$f" "$sg" "$d" >&2
done

log "Findings (behaviour the partner will meet, reported apart from failures)"
grep -h "FINDING:" "$LOGDIR"/*.log 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/  /' >&2 || echo "  (none)" >&2

log "Skips (what is NOT covered, and why)"
grep -h "SKIP:" "$LOGDIR"/*.log 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/  /' >&2 || echo "  (none)" >&2

# ── §8 acceptance map ──────────────────────────────────────────────────────
#
# `live` = proved against the real chain and the real coordinator.
# `stub`  = proved through the §10 stub: our side of the leased mode in full,
#           the partner's on-chain panic not included.
# `waits-TLA` / `external` = named so nobody reads a blank as "covered".
log "§8 acceptance R0–R12"
cat >&2 <<'MAP'
  R0   executor→asset w_execute_extension executes and is tracked
       live   decoder §D0 (executed, tx hash), endpoints §E11'''' (the builder), lifecycle §R5a
  R1   a binding only after the owner's authorization and on-chain confirmation
       live   endpoints §E5/E5' (pending claims nothing, active is exclusive), fixture (kit → active)
       stub   lease §"the leased binding is ACTIVE" (the partner's view believed, then verified)
  R2   a limit breached INSIDE args → refused before signing
       live   decoder §R2 (250 NEAR nested, 1 yocto outside) and §R2-aggregate (split payment, one rule)
  R3   ft_transfer through a permitted token contract to a foreign logical recipient → refused
       live   decoder §R3, custody §F3/§G1 (per-token cap and token allowlist over the DECODED move)
  R4   any AddExtension / RemoveExtension / SetSignatureMode → hard deny
       live   decoder §R4 (all three ops, plus one smuggled beside a legal transfer)
  R5   the binding stops executing after transfer / recovery / revoke / expiry
       live   lifecycle §R5b–R5g (executor cut, wiped account, re-bind, DELETE)
       stub   lease §C-* (frozen, parked, suspended, lease expired) and §ROT (ownership rotation)
       stub   lease §PAIR1–3 — the collection's `nft_token` held against the account's
              `nft_item_info`: a disagreement suspends AND the gate refuses (registry_disagrees,
              not terminal); agreement brings the lane back without re-binding
       live   bravo §B6 — the rotation HoS performs on request (ROTATED=1 phase):
              transitional refusal, closure recorded, then binding_ended
       live   lease §W — the revoke webhook, when `BINDING_WEBHOOK_SECRET` is exported.
              Without it the suite says so rather than passing quietly; the secret is in
              `prod_configs/coordinator/.env.testnet` and the coordinator must be carrying it
  R6   gas: source, submit, retry, replay specified and exercised
       live   endpoints §E12 (the balance is on /address), custody §L (one spend at a time)
       live   gas §F1/§F4 — the 0.05 NEAR warning on the binding flips both ways, and the
              threshold it measured against is named
       live   gas §F2 — an executor starved below the cost of a call is refused 402
              wallet_underfunded, naming what it holds and what the call costs, with the
              money still sitting untouched in the bound account
       live   gas §F3 — and the refused request is SETTLED (failed / never_admitted) rather
              than left for a repair to reconstruct. Needs PSQL_CMD
       live   gas §F4 — the same envelope goes through once the executor can pay, which is
              what makes the three refusals above refusals ABOUT GAS
  R7   reads do not mix the two identities
       live   endpoints §E10/E12/E13 (asset vs executor, intents sent to the right door, /balance unmoved)
       stub   lease reserve_yocto is read from hos_agent_status (§R1)
       live   bravo §B3 — the floor binds on the real account (ceiling above balance),
              §B4 — the item fence, the collection wall and the own-collection rule on
              the real grant, §B5 — carry-forward across a refill. Run APART from this
              runner (wk_-authenticated: `hos_lease_bravo_e2e.sh`), like the alpha suite
  R8   one operation traceable from API to inner receipts
       live   identity §I7 walks the HTTPS door from the only handle a client is given — the call id
              — through https_calls, the execution request, the job and the worker that ran it, to
              the TEE attestation at /attestations/by-call
       live   bound_identity_onchain §B7 walks the other door from the only handle a caller holds
              there — the transaction hash — to the chain's own inner receipts, the job and worker,
              the priced record, and /attestations/by-tx. Run APART from this runner: it needs an
              existing binding (BINDING_SEED + ASSET), which nothing here produces
       live   attribution on both doors: identity §I6/§I6b and §B6 — the request row and the
              earnings row name the PAYER, never the account the guest borrowed
       needs  PSQL_CMD. Without it those sections skip and say so, and nothing below the answer
              envelope is judged at all
  R9   an unsupported impl_version is rejected before signing
       live   endpoints §E3i (PUT refuses version 999, names the supported set, says terminal)
       stub   lease §C-version (a chain that reports version 5 → unsupported_wallet_implementation)
  R10  a confidential operation end to end
       live   endpoints §E16 — the TESTNET half: the routes answer 503 with NO `Retry-After`
              and a sentence naming the deployment, so a client cannot read "off" as "busy"
       live   the `confidential` capability is a per-wallet policy gate like the others
              (`Capabilities::confidential`), which is what R10 asks of the policy shape
       external the operation itself is mainnet only — there are no solvers on testnet
  R11  sign-in / proof of ownership
       external not part of this integration: the wallet's own NEP-413 path
  R12  a spend over the granted budget is refused, and reported as terminal
       live   lease §G4/§G5 and live-grant §G8/§G9 — the per-token and native walls,
              with §G9 asserting the `terminal` flag the client routes on
       live   lease §G0/§R12 — the chain's OWN refusal: the stub answers views and has
              no `w_execute_extension`, so a request the pre-flight admits comes back
              422 `chain_refused` with no `Retry-After`. That shape is unreachable
              through the grant walls above, which our pre-flight answers first
MAP

log "Verdict"
if (( FAILED_SUITES > 0 )); then
  echo "  $FAILED_SUITES suite(s) failed — see $LOGDIR" >&2
  exit 1
fi
if (( NOTHING_SUITES > 0 )); then
  echo "  $NOTHING_SUITES suite(s) judged NOTHING — the run is silent about what they cover," >&2
  echo "  not green on it. Read their SKIP lines above and supply what they asked for." >&2
  echo "  Everything that did run, passed. Logs in $LOGDIR" >&2
  exit 0
fi
echo "  every suite passed. Logs in $LOGDIR" >&2
