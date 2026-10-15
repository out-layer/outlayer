#!/usr/bin/env bash
# Post-deploy smoke test for the coordinator + keystore release.
#
# WHY THIS EXISTS: the unit suites check logic inside a process. Almost everything that actually
# breaks a release breaks at a seam they cannot see — a keystore that came up but never got its
# DAO vote, a route that moved, a token that was not rotated, a timeout that is now too short, a
# certificate the edge will not accept. This runs the real endpoints and names the first thing
# that is wrong, in the order you would want to hear it.
#
# Run it IMMEDIATELY after deploying, before telling anyone the release is out.
#
#   scripts/smoke_after_deploy.sh testnet
#   scripts/smoke_after_deploy.sh mainnet
#
# Config comes from `scripts/.env` (see scripts/.env.example). Checks whose config is missing are
# reported SKIP, not PASS — a skipped check has verified nothing, and the summary says so.
#
# Exit code: 0 only if nothing FAILED. Skips do not fail the run, but they are counted.

set -uo pipefail

NETWORK="${1:-}"
if [ "$NETWORK" != "testnet" ] && [ "$NETWORK" != "mainnet" ]; then
  echo "usage: $0 <testnet|mainnet>" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/.env"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
else
  echo "note: $ENV_FILE not found — every configured check will SKIP. See scripts/.env.example." >&2
fi

# Per-network config. Suffix the variables in scripts/.env with _TESTNET / _MAINNET.
UP="$(echo "$NETWORK" | tr '[:lower:]' '[:upper:]')"
var() { eval "printf '%s' \"\${${1}_${UP}:-}\""; }

API_URL="$(var SMOKE_API_URL)"
API_URL_LEGACY="$(var SMOKE_API_URL_LEGACY)"
KEYSTORE_URL="$(var SMOKE_KEYSTORE_URL)"
# TWO different tokens — they authenticate to two different services and are not
# interchangeable. The worker holds both: `KEYSTORE_AUTH_TOKEN` (→ keystore) and
# `API_AUTH_TOKEN` (→ coordinator), see deploy/self-hosted-tdx/worker/.env.*
KEYSTORE_TOKEN="$(var SMOKE_KEYSTORE_TOKEN)"
COORDINATOR_TOKEN="$(var SMOKE_COORDINATOR_TOKEN)"
VAULT_ID="$(var SMOKE_VAULT_ID)"
BIG_REPO="$(var SMOKE_BIG_REPO)"
BIG_REPO_COMMIT="$(var SMOKE_BIG_REPO_COMMIT)"

# Accept a pasted GitHub commit URL where a bare SHA belongs — it is the natural thing to copy out
# of a browser, and the alternative is a confusing 404 much later, from an endpoint that looks
# broken rather than misconfigured. The repo is derived from the same URL when it was not given
# separately, so one line is enough to enable this check.
case "$BIG_REPO_COMMIT" in
  https://github.com/*/commit/*)
    if [ -z "$BIG_REPO" ]; then
      BIG_REPO="$(printf '%s' "$BIG_REPO_COMMIT" | sed -E 's#(https://github\.com/[^/]+/[^/]+)/commit/.*#\1#')"
    fi
    BIG_REPO_COMMIT="$(printf '%s' "$BIG_REPO_COMMIT" | sed -E 's#.*/commit/##' | sed -E 's#[^0-9a-fA-F].*##')"
    ;;
esac

PASS=0; FAIL=0; SKIP=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; SKIP=$((SKIP+1)); }

# curl helper: prints "<status>\n<body>"; never hangs the run.
req() { curl -sS --max-time 30 -o /tmp/smoke_body.$$ -w '%{http_code}' "$@" 2>/tmp/smoke_err.$$ || echo "000"; }
body() { cat /tmp/smoke_body.$$ 2>/dev/null; }
cleanup() { rm -f /tmp/smoke_body.$$ /tmp/smoke_err.$$; }
trap cleanup EXIT

echo
echo "OutLayer post-deploy smoke — $NETWORK"
echo

# ---------------------------------------------------------------------------
echo "keystore"
# ---------------------------------------------------------------------------

# 1. Liveness. Deliberately NOT proof of readiness: /health answers 200 even while the keystore
#    is waiting for its DAO vote, which is exactly the state that breaks custody silently.
if [ -z "$KEYSTORE_URL" ]; then
  skip "/health reachable" "SMOKE_KEYSTORE_URL_$UP not set"
else
  code="$(req "$KEYSTORE_URL/health")"
  if [ "$code" = "200" ]; then pass "/health reachable ($code)"
  else fail "/health reachable" "got $code — keystore is down or the gateway/cert is wrong"; fi
fi

# 2. Readiness, via the ONE endpoint that is gated on it. A keystore that restarted and never got
#    its DAO vote answers 401 here while /health still says ok. This is the single most valuable
#    check in the file: it is the failure that has taken custody down before and gone unnoticed.
if [ -z "$KEYSTORE_URL" ]; then
  skip "keystore is READY (vrf/pubkey)" "SMOKE_KEYSTORE_URL_$UP not set"
else
  code="$(req "$KEYSTORE_URL/vrf/pubkey")"
  if [ "$code" = "200" ]; then pass "keystore is READY (vrf/pubkey 200)"
  elif [ "$code" = "401" ]; then fail "keystore is READY" "401 — NOT ready: it is waiting for a DAO vote. Vote NOW (the window is ~30 min) or it wedges."
  else fail "keystore is READY" "got $code"; fi
fi

# 3. The new admin endpoint, and the fact that it is NOT public. Both directions matter: the list
#    of loaded vaults is operational detail, and a router refactor could expose it.
if [ -z "$KEYSTORE_URL" ] || [ -z "$KEYSTORE_TOKEN" ]; then
  skip "/admin/loaded-vaults (auth + shape)" "needs SMOKE_KEYSTORE_URL_$UP and SMOKE_KEYSTORE_TOKEN_$UP"
else
  code="$(req "$KEYSTORE_URL/admin/loaded-vaults")"
  if [ "$code" = "401" ]; then pass "/admin/loaded-vaults refuses an anonymous caller (401)"
  else fail "/admin/loaded-vaults refuses an anonymous caller" "got $code — MUST be 401. Anyone can list vaults."; fi

  code="$(req -H "Authorization: Bearer $KEYSTORE_TOKEN" "$KEYSTORE_URL/admin/loaded-vaults")"
  if [ "$code" = "200" ] && body | grep -q '"count"'; then
    pass "/admin/loaded-vaults with the keystore token ($(body | head -c 120))"
  else
    fail "/admin/loaded-vaults with the keystore token" "got $code: $(body | head -c 200)"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "coordinator → keystore"
# ---------------------------------------------------------------------------

# 4. The public VRF proxy. Exercises, in one request: the keystore being ready, the pooled client,
#    the non-2xx check (a keystore error must NOT come back as 200), the IP rate limiter and the
#    CORS layer that the router rework moved.
if [ -z "$API_URL" ]; then
  skip "coordinator /vrf/pubkey proxy" "SMOKE_API_URL_$UP not set"
else
  code="$(req "$API_URL/vrf/pubkey")"
  if [ "$code" = "200" ] && body | grep -q "vrf_public_key"; then
    pass "coordinator /vrf/pubkey proxies a real key"
  elif [ "$code" = "200" ]; then
    fail "coordinator /vrf/pubkey" "200 but no key in the body — an error leaked through as success: $(body | head -c 200)"
  elif [ "$code" = "503" ]; then
    fail "coordinator /vrf/pubkey" "503 — keystore unreachable or not ready (check #2 above)"
  else
    fail "coordinator /vrf/pubkey" "got $code: $(body | head -c 200)"
  fi
fi

# 5. A vault-scoped pubkey. Covers the 120s keystore client (this path can wait on an on-chain MPC
#    CKD derivation) and the vault gate. On a COLD vault the first call is the slow one — that is
#    expected, and it is the call that proves the derivation path works end to end.
if [ -z "$API_URL" ] || [ -z "$VAULT_ID" ]; then
  skip "vault-scoped /secrets/pubkey" "OPTIONAL — set SMOKE_VAULT_ID_$UP only if you want it; the first call after a keystore restart pays for an on-chain CKD derivation out of that vault"
else
  started=$(date +%s)
  # Shape verified against the live endpoint: accessor + owner + secrets_json are all required
  # (a bare {"seed":...} is rejected 422 by the body deserializer, before anything is exercised).
  code="$(req -X POST -H 'Content-Type: application/json' -H "X-Customer-Vault: $VAULT_ID" \
        -d '{"accessor":{"type":"Repo","repo":"github.com/outlayer/smoke-check"},"owner":"smoke.testnet","secrets_json":"{}"}' \
        "$API_URL/secrets/pubkey")"
  elapsed=$(( $(date +%s) - started ))
  if [ "$code" = "200" ]; then pass "vault-scoped /secrets/pubkey (${elapsed}s, vault $VAULT_ID)"
  elif [ "$code" = "402" ]; then fail "vault-scoped /secrets/pubkey" "402 — the vault cannot pay for its CKD derivation: $(body | head -c 200)"
  else fail "vault-scoped /secrets/pubkey" "got $code after ${elapsed}s: $(body | head -c 200)"; fi
fi

# 6. The branch-count guard. Only reachable with a worker token from a worker host (the route
#    is worker-protected and answers WORKER_ALLOWED_IPS only), and it is the one check that
#    needs a repository with more than 5 branches. Part of the build path, which is off unless
#    the coordinator has BUILDS_ENABLED.
if [ -z "$API_URL" ] || [ -z "$COORDINATOR_TOKEN" ] || [ -z "$BIG_REPO" ] || [ -z "$BIG_REPO_COMMIT" ]; then
  skip "branch-count guard returns 422" "needs SMOKE_COORDINATOR_TOKEN_$UP + SMOKE_BIG_REPO_$UP + SMOKE_BIG_REPO_COMMIT_$UP (repo with >5 branches)"
else
  code="$(printf 'Authorization: Bearer %s\n' "$COORDINATOR_TOKEN" | req -H @- \
        --get --data-urlencode "repo=$BIG_REPO" --data-urlencode "commit=$BIG_REPO_COMMIT" \
        "$API_URL/github/resolve-branch")"
  if [ "$code" = "422" ] && body | grep -q "branches (limit"; then
    pass "branch-count guard returns 422 with an actionable message"
  elif [ "$code" = "403" ]; then
    skip "branch-count guard" "the coordinator answers worker routes only from worker hosts (WORKER_ALLOWED_IPS); run this from one"
  elif [ "$code" = "200" ]; then
    # NOT a failure: the fast path (`branches-where-head`, a single GitHub call) resolved it, so
    # the per-branch scan the guard protects was never entered. Only a commit that is not the head
    # of any branch reaches the guard — pick an older one.
    skip "branch-count guard" "inconclusive: this commit is the HEAD of a branch, so it resolved via the fast path without reaching the guard. Use an OLDER commit: $(body | head -c 120)"
  else
    fail "branch-count guard" "got $code (expected 422): $(body | head -c 200)"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "api hostnames"
# ---------------------------------------------------------------------------

# 7. Both API hostnames serve the same origin, byte for byte. Guards the migration window: the old
#    name must keep working unchanged while callers move to the new one.
if [ -z "$API_URL" ] || [ -z "$API_URL_LEGACY" ]; then
  skip "old and new API hostnames agree" "needs SMOKE_API_URL_$UP and SMOKE_API_URL_LEGACY_$UP"
else
  new_body="$(curl -sS --max-time 30 "$API_URL/public/stats" 2>/dev/null)"
  old_body="$(curl -sS --max-time 30 "$API_URL_LEGACY/public/stats" 2>/dev/null)"
  if [ -z "$new_body" ] || [ -z "$old_body" ]; then
    fail "old and new API hostnames agree" "one of them returned nothing"
  elif [ "$new_body" = "$old_body" ]; then
    pass "old and new API hostnames serve the same origin"
  else
    # Live counters can move between the two calls; only flag a shape difference.
    fail "old and new API hostnames agree" "bodies differ — if only counters moved this is benign, otherwise they point at different upstreams"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "workers"
# ---------------------------------------------------------------------------

# 8. Workers reconnected after the keystore restart. Every TEE session lives in the keystore's
#    memory, so a restart invalidates all of them; the workers re-handshake on their next call.
#    A fleet that is online but has zero sessions has not talked to the keystore yet.
if [ -z "$API_URL" ]; then
  skip "workers are online" "SMOKE_API_URL_$UP not set"
else
  code="$(req "$API_URL/public/workers")"
  online="$(body | grep -o '"status":"online"' | wc -l | tr -d ' ')"
  if [ "$code" = "200" ] && [ "${online:-0}" -gt 0 ]; then
    pass "workers online: $online"
  else
    fail "workers are online" "got $code, online=$online — after a keystore release, check the workers were redeployed AFTER it"
  fi
fi

echo
echo "-----------------------------------------------------------"
printf 'PASS %d   FAIL %d   SKIP %d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$SKIP" -gt 0 ]; then
  echo "note: a SKIP has verified NOTHING. Fill in scripts/.env to close the gaps."
fi
if [ "$FAIL" -gt 0 ]; then
  echo "RELEASE IS NOT VERIFIED — fix the failures above before announcing it."
  exit 1
fi
echo "All executed checks passed."
