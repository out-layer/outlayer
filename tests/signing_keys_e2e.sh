#!/usr/bin/env bash
#
# Signing keys end to end, on testnet: `wasi-examples/signing-key-probe` run by
# a deployed worker against a deployed keystore, on chain, as two callers.
#
# What each row pins:
#   S1  every operation of the project build answers, and each signature
#       verifies HERE, with an independent ed25519 (PyNaCl or `cryptography`)
#   S2  alpha ≠ beta — two paths, two keys
#   S3  two callers get two keys for one path ($PARENT and $CALLER2)
#   S4  the same caller gets the same keys on a second run
#   S5  a second version of the project (the `v2` build, another sha256) keeps
#       every `project` key — and it is the v2 bytes that ran
#   S6  the `wasm` build run directly from its wasm URL gets its `code` key; the
#       `wasm-v2` build, another sha256, gets another key; a repeat, the same
#   S7  bind must match how the code is run: the `wasm` build published as a
#       project version and run through the project → refused; the project
#       build run directly from its wasm URL → refused. No key in either answer
#   S8  a GitHub run whose manifest declares signing_keys → refused before it
#       runs, no key material in the answer; with GITHUB_PROJECT_VERSION=1, a
#       project version published from that repository too. Needs
#       GITHUB_PROBE_REPO + GITHUB_PROBE_COMMIT (a repository whose ROOT is this
#       probe, the commit pushed): the platform builds a repository at its root
#       and has no subdirectory field, so out-layer/outlayer cannot be used
#   S9  every attack answers with a status and a message, in a run that succeeds
#   S10 naming a vault for a key declared without one → err
#   S11 no seed in any answer: every 32-byte value in every answer of the run
#       (hex or base64) is tried as an ed25519 seed, and none derives a public
#       key the run has seen
#   S12 sign_nep413 → the wallet-style answer, verified HERE against a NEP-413
#       hash rebuilt independently (struct + hashlib); a tampered message,
#       recipient or nonce does not verify
#   S22 caller predecessor (the `project-pred` build, a version of the project):
#       on a direct call the predecessor key at alpha is NOT the signer key at
#       alpha, though the account is one (the caller kind is a derivation
#       segment); $CALLER2 gets another. Relayed through $RELAY_CONTRACT: the
#       guest sees the relay as NEAR_PREDECESSOR_ID and the signer as
#       NEAR_USER_ACCOUNT_ID; the key is neither of $PARENT's; $CALLER2 through
#       the same relay gets the SAME key — the relay contract's; it signs, and
#       the signature verifies HERE; the `project` build relayed keeps the
#       signer's alpha. Without RELAY_CONTRACT the relayed half SKIPS, loudly
#
# SKIPs loudly, whole, when the keystore or the worker predates signing keys.
#
# Needs: PARENT (owns the project, first caller; key in the keychain), CALLER2
# (a second account with its key in the legacy keychain), the `outlayer` CLI
# logged in on testnet (any account: it pays for the FastFS uploads), python3
# with PyNaCl or `cryptography`,
# near, outlayer, jq, curl, cargo + wasm-tools (the build). The RPC is keyed
# through tests/lib/rpc.sh.
# For S22's relayed half: RELAY_CONTRACT, the testnet account of the deployed
# wasi-examples/test-storage-ark/relay-contract (its `outlayer()` must be
# $CONTRACT_ID).
#
# Env: OFFLINE=1 (dry run only: no chain or GitHub reads; ignored with --apply).
#
# Money: five FastFS uploads (~230 KB each), project storage, and one on-chain
# run per probe at $DEPOSIT (~27 runs; a relayed run's unused deposit comes
# back to its signer, as a direct run's does).
#
# Run:
#   PARENT=you.testnet CALLER2=friend.testnet ./tests/signing_keys_e2e.sh            # dry run: checks, no writes
#   PARENT=you.testnet CALLER2=friend.testnet ./tests/signing_keys_e2e.sh --apply    # build, upload, publish, run
#   … GITHUB_PROBE_REPO=https://github.com/you/signing-key-probe GITHUB_PROBE_COMMIT=<sha> … --apply
#   … RELAY_CONTRACT=relay.you.testnet … --apply                                     # with S22's relayed half

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

PARENT="${PARENT:-}"
CALLER2="${CALLER2:-}"
PROJECT_NAME="${PROJECT_NAME:-signing-key-probe}"
PROJECT="$PARENT/$PROJECT_NAME"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
GITHUB_PROBE_REPO="${GITHUB_PROBE_REPO:-}"
GITHUB_PROBE_COMMIT="${GITHUB_PROBE_COMMIT:-}"
GITHUB_PROJECT_VERSION="${GITHUB_PROJECT_VERSION:-0}"
RELAY_CONTRACT="${RELAY_CONTRACT:-}"
OFFLINE="${OFFLINE:-0}"
[[ "$APPLY" == true ]] && OFFLINE=0
PROBE_DIR="$REPO_ROOT/wasi-examples/signing-key-probe"
VARIANTS="$PROBE_DIR/target/variants"
export OUTLAYER_NETWORK="$NETWORK"

# Every answer of the run, for S11.
ANSWERS=$(mktemp -t signing_keys_e2e.XXXXXX)
# Every public key the run has seen, for S11.
SEEN_KEYS=$(mktemp -t signing_keys_e2e_keys.XXXXXX)
trap 'rm -f "$ANSWERS" "$SEEN_KEYS"' EXIT

# ── helpers ──────────────────────────────────────────────────────────────────

# The keyed RPC URL reaches curl on stdin (a config line written by a shell
# builtin), never on a command line.
rpc_post() { # rpc_post <json-body>
  printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}

view() { # view <account> <method> <args-json> — the decoded result, or empty
  rpc_post "$(jq -nc --arg a "$1" --arg m "$2" --arg g "$(printf '%s' "$3" | base64 | tr -d '\n')" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}

version_on_chain() { # version_on_chain <version_key> — the version's source kind, or empty
  view "$CONTRACT_ID" get_version "$(jq -nc --arg p "$PROJECT" --arg v "$1" '{project_id:$p, version_key:$v}')" \
    | jq -r 'select(. != null) | .source | keys[0] // empty' 2>/dev/null
}

sha_of() { shasum -a 256 "$1" | cut -d' ' -f1; }

# Per-build values in plain variables — the macOS bash (3.2) has no associative
# arrays. `var_name hash project-v2` → H_project_v2.
var_name() { printf '%s_%s' "$( [[ $1 == hash ]] && echo H || echo U )" "${2//-/_}"; }
set_for() { printf -v "$(var_name "$1" "$2")" '%s' "$3"; }
get_for() { local n; n=$(var_name "$1" "$2"); printf '%s' "${!n:-}"; }

signer_flag() { [[ "$1" == "$PARENT" ]] && echo with-keychain || echo with-legacy-keychain; }

# One contract call, its whole transcript on stdout — the logs and the return
# value included, which is where a run's event and answer are read from.
call_on() { # call_on <signer> <receiver> <method> <args-json> <deposit>
  near contract call-function as-transaction "$2" "$3" json-args "$4" \
    prepaid-gas '300.0 Tgas' attached-deposit "$5" sign-as "$1" network-config "$NETWORK" "sign-$(signer_flag "$1")" send 2>&1
}
call() { call_on "$1" "$CONTRACT_ID" "$2" "$3" "$4"; } # call <signer> <method> <args-json> <deposit>

# ── one run, on chain ────────────────────────────────────────────────────────
#
# `run_src <signer> <source-json> <input-json>` sets RUN_OK (true / false /
# absent), RUN_ERR (the refusal) and RUN_OUT (the probe's own answer), and
# appends everything that came back to $ANSWERS. The completion event is read
# from the send's own transcript, or polled from the transaction when the run
# outlives it (a GitHub source compiles first). `run_relayed` is the same run
# reached through $RELAY_CONTRACT: its predecessor is the relay, its signer
# `<signer>`, and the relay returns the run's answer as its own.
RUN_OK=""; RUN_ERR=""; RUN_OUT=""
exec_args() { # exec_args <source-json> <input-json>
  jq -nc --argjson s "$1" --arg i "$2" \
    '{source:$s, input_data:$i, response_format:"Json",
      resource_limits:{max_instructions:10000000000,max_memory_mb:128,max_execution_seconds:60}}'
}
run_src()     { run_on "$1" "$CONTRACT_ID" request_execution "$(exec_args "$2" "$3")"; }
run_relayed() { run_on "$1" "$RELAY_CONTRACT" relay "$(exec_args "$2" "$3")"; }
run_on() { # run_on <signer> <receiver> <method> <args-json>
  local signer=$1 out tx ev logs="" i
  out=$(call_on "$signer" "$2" "$3" "$4" "$DEPOSIT")
  printf '%s\n' "$out" >> "$ANSWERS"
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  tx=$(grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$out" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1)
  if [[ -z "$ev" && -n "$tx" ]]; then
    for i in $(seq 1 90); do
      logs=$(rpc_post "$(jq -nc --arg t "$tx" --arg s "$signer" \
        '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
      printf '%s\n' "$logs" >> "$ANSWERS"
      ev=$(jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' <<<"$logs" 2>/dev/null \
        | grep -o 'EVENT_JSON:.*execution_completed.*' | sed 's/^EVENT_JSON://' | head -1)
      [[ -n "$ev" ]] && break
      # A receipt that failed before a run was asked for: no event will come.
      jq -e '[.result.receipts_outcome[]?.outcome.status | select(has("Failure"))] | length > 0' <<<"$logs" >/dev/null 2>&1 && break
      (( i % 9 == 0 )) && note "still working… ~$((i*20))s"
      sleep 20
    done
  fi
  RUN_OUT=$(awk '/Function execution return value/{getline; print}' <<<"$out" \
    | jq -c 'select(. != null) | if type=="string" then fromjson else . end' 2>/dev/null)
  if [[ -z "$RUN_OUT" && -n "$logs" ]]; then
    RUN_OUT=$(jq -r '.result.status.SuccessValue // empty | @base64d' <<<"$logs" 2>/dev/null \
      | jq -c 'select(. != null) | if type=="string" then fromjson else . end' 2>/dev/null)
  fi
  if [[ -z "$ev" ]]; then
    RUN_OK=absent
    RUN_ERR=$( { grep -iE 'error|panick|failed' <<<"$out" | head -2
                 [[ -n "$logs" ]] && jq -r '.result.receipts_outcome[]?.outcome.status.Failure? // empty | tostring' <<<"$logs" 2>/dev/null | head -2
               } | tr '\n' ' ' | head -c 300)
    return 0
  fi
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev" 2>/dev/null)
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev" 2>/dev/null)
}

project_src() { # project_src [version_key]
  if [[ -n "${1:-}" ]]; then jq -nc --arg p "$PROJECT" --arg v "$1" '{Project:{project_id:$p, version_key:$v}}'
  else jq -nc --arg p "$PROJECT" '{Project:{project_id:$p}}'; fi
}
wasm_src() { jq -nc --arg u "$1" --arg h "$2" '{WasmUrl:{url:$u, hash:$h, build_target:"wasm32-wasip2"}}'; }
github_src() { jq -nc --arg r "$GITHUB_PROBE_REPO" --arg c "$GITHUB_PROBE_COMMIT" '{GitHub:{repo:$r, commit:$c, build_target:"wasm32-wasip2"}}'; }

out_field() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$RUN_OUT" 2>/dev/null; }

# A run that must have happened, with the probe's answer `ok`.
ran_ok() { # ran_ok <row> — 0 when the run happened and answered ok
  if [[ "$RUN_OK" != "true" ]]; then
    fail "$1 — the run did not happen ($RUN_OK): $(head -c 300 <<<"$RUN_ERR")"; return 1
  fi
  if [[ "$(out_field .status)" != "ok" ]]; then
    fail "$1 — the probe answered $(out_field .status): $(out_field .message | head -c 300)"; return 1
  fi
  return 0
}

# A run that must have been refused before the module ran, carrying no key.
refused_without_keys() { # refused_without_keys <row> <grep-pattern>
  if [[ "$RUN_OK" == "true" ]]; then
    fail "$1 — the run HAPPENED: $(head -c 300 <<<"$RUN_OUT")"; return 1
  fi
  if [[ "$RUN_OK" == "absent" ]]; then
    fail "$1 — nothing answered; a timeout is not a refusal: $RUN_ERR"; return 1
  fi
  if jq -e '[.. | objects | select(has("public_key") or has("signature") or has("keys") or has("accountId"))] | length > 0' \
       <<<"${RUN_OUT:-null}" >/dev/null 2>&1; then
    fail "$1 — refused, and yet key material came back: $(head -c 300 <<<"$RUN_OUT")"; return 1
  fi
  if ! grep -qiE "$2" <<<"$RUN_ERR"; then
    fail "$1 — refused, but not for the key rule: $(head -c 300 <<<"$RUN_ERR")"; return 1
  fi
  pass "$1 — refused: $(head -c 200 <<<"$RUN_ERR")"
}

# ed25519 verification here, by a library that is neither the worker's nor the
# guest's.
verify_local() { # verify_local <public_key_hex> <message_hex> <signature_hex>
  python3 - "$1" "$2" "$3" <<'PY'
import sys
pk, msg, sig = (bytes.fromhex(a) for a in sys.argv[1:4])
try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    try:
        VerifyKey(pk).verify(msg, sig); print("ok")
    except BadSignatureError:
        print("bad")
except ImportError:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg); print("ok")
    except InvalidSignature:
        print("bad")
PY
}

# NEP-413's hash, rebuilt here: borsh by hand with struct, sha256 with hashlib.
nep413_hash_local() { # nep413_hash_local <message> <nonce_hex> <recipient> [callback_url]
  python3 - "$@" <<'PY'
import hashlib, struct, sys
message, nonce, recipient = sys.argv[1], bytes.fromhex(sys.argv[2]), sys.argv[3]
callback = sys.argv[4] if len(sys.argv) > 4 else None
s = lambda b: struct.pack('<I', len(b)) + b
payload = s(message.encode()) + nonce + s(recipient.encode())
payload += b'\x00' if callback is None else b'\x01' + s(callback.encode())
print(hashlib.sha256(struct.pack('<I', 2**31 + 413) + payload).hexdigest())
PY
}

remember_keys() { # remember_keys — every public key in RUN_OUT, for S11
  jq -r '.. | objects | .public_key? // empty' <<<"$RUN_OUT" 2>/dev/null >> "$SEEN_KEYS"
}

# ── preflight ────────────────────────────────────────────────────────────────

note "RPC: $(rpc_url_public)"
for tool in jq curl near outlayer cargo python3 shasum openssl xxd; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
if ! python3 -c 'import nacl' 2>/dev/null && ! python3 -c 'import cryptography' 2>/dev/null; then
  echo "✗ python3 needs PyNaCl or cryptography: the signatures are verified here, independently" >&2; exit 1
fi
[[ -n "$PARENT" && -n "$CALLER2" ]] || { echo "USAGE: PARENT=you.testnet CALLER2=friend.testnet $0 [--apply]" >&2; exit 1; }
[[ "$PARENT" != "$CALLER2" ]] || { echo "✗ CALLER2 must be another account than PARENT" >&2; exit 1; }
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
CREDS_MISSING=""
for acct in "$PARENT" "$CALLER2"; do
  [[ -f "$CREDS_DIR/$acct.json" ]] || CREDS_MISSING+="$acct "
done
if [[ -n "$CREDS_MISSING" ]]; then
  if [[ "$APPLY" == true ]]; then echo "✗ no key in $CREDS_DIR for: $CREDS_MISSING" >&2; exit 1; fi
  warn "no key in $CREDS_DIR for: ${CREDS_MISSING}— --apply will stop here"
fi

# The GitHub row's commit must be one the platform can fetch.
GITHUB_READY=false
GITHUB_WHY="GITHUB_PROBE_REPO and GITHUB_PROBE_COMMIT are unset"
if [[ -n "$GITHUB_PROBE_REPO" && -n "$GITHUB_PROBE_COMMIT" && "$OFFLINE" == 1 ]]; then
  GITHUB_WHY="OFFLINE=1: $GITHUB_PROBE_REPO@${GITHUB_PROBE_COMMIT:0:12} not checked"
elif [[ -n "$GITHUB_PROBE_REPO" && -n "$GITHUB_PROBE_COMMIT" ]]; then
  slug=$(sed -E 's#^https://github.com/##; s#\.git$##; s#/$##' <<<"$GITHUB_PROBE_REPO")
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://api.github.com/repos/$slug/commits/$GITHUB_PROBE_COMMIT")
  if [[ "$code" == "200" ]]; then
    GITHUB_READY=true
  else
    GITHUB_WHY="$GITHUB_PROBE_REPO@${GITHUB_PROBE_COMMIT:0:12} is not a pushed public commit (GitHub answered $code)"
  fi
fi

# S22's relayed half needs the relay deployed, relaying to this contract. A
# relay named but unusable stops --apply: the rows it was named for would not run.
RELAY_READY=false
if [[ -z "$RELAY_CONTRACT" ]]; then
  RELAY_WHY="RELAY_CONTRACT is unset — deploy wasi-examples/test-storage-ark/relay-contract (its README) and export its account"
elif [[ "$OFFLINE" == 1 ]]; then
  RELAY_WHY="OFFLINE=1: $RELAY_CONTRACT not checked"
else
  relay_target=$(view "$RELAY_CONTRACT" outlayer '{}' | jq -r 'select(type == "string")' 2>/dev/null)
  if [[ "$relay_target" == "$CONTRACT_ID" ]]; then
    RELAY_READY=true
  else
    RELAY_WHY="$RELAY_CONTRACT does not relay to $CONTRACT_ID (its outlayer(): '${relay_target:-unreadable}')"
    [[ "$APPLY" == true ]] && { echo "✗ $RELAY_WHY" >&2; exit 1; }
  fi
fi

if [[ "$APPLY" != true ]]; then
  log "dry run — nothing is built, uploaded, published or run"
  sed -n '3,/^$/p' "$0" >&2
  if [[ "$OFFLINE" == 1 ]]; then
    note "OFFLINE=1: the project and its versions are not read from the chain"
  else
    note "project: $PROJECT ($(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r 'if .project_id then "on chain, active " + .active_version else "not on chain yet" end' 2>/dev/null || echo 'unreadable'))"
  fi
  for v in project project-v2 project-pred wasm wasm-v2; do
    f="$VARIANTS/signing-key-probe-$v.wasm"
    if [[ -f "$f" ]]; then
      h=$(sha_of "$f")
      if [[ "$OFFLINE" == 1 ]]; then kind="(not read)"; else kind=$(version_on_chain "$h"); fi
      note "$v: built locally, sha256 $h; as a version of $PROJECT: ${kind:-absent}"
    else
      note "$v: not built yet (--apply runs $PROBE_DIR/build.sh)"
    fi
  done
  if [[ "$GITHUB_READY" == true ]]; then note "S8: $GITHUB_PROBE_REPO@${GITHUB_PROBE_COMMIT:0:12} is pushed"; else warn "S8 will SKIP: $GITHUB_WHY"; fi
  if [[ "$RELAY_READY" == true ]]; then note "S22 relayed: $RELAY_CONTRACT relays to $CONTRACT_ID"; else warn "S22 relayed half will SKIP: $RELAY_WHY"; fi
  echo "  Pass --apply to run." >&2
  exit 0
fi

# ── setup: build, upload, publish ────────────────────────────────────────────

log "build the probe"
(cd "$PROBE_DIR" && ./build.sh >/dev/null) || { echo "✗ $PROBE_DIR/build.sh failed" >&2; exit 1; }
for v in project project-v2 project-pred wasm wasm-v2; do
  set_for hash "$v" "$(sha_of "$VARIANTS/signing-key-probe-$v.wasm")"
  note "$v sha256 $(get_for hash "$v")"
done

log "upload to FastFS"
for v in project project-v2 project-pred wasm wasm-v2; do
  up=$(OUTLAYER_RPC_URL="$RPC_URL" outlayer upload "$VARIANTS/signing-key-probe-$v.wasm" 2>&1)
  url=$(grep -oE 'https://[A-Za-z0-9._-]+\.fastfs\.io/[^[:space:]"]+\.wasm' <<<"$up" | head -1)
  if [[ -z "$url" ]]; then
    echo "✗ upload of $v gave no FastFS URL: $(tail -3 <<<"$up" | tr '\n' ' ' | head -c 300)" >&2; exit 1
  fi
  got=$(curl -sL --max-time 60 "$url" | shasum -a 256 | cut -d' ' -f1)
  [[ "$got" == "$(get_for hash "$v")" ]] || { echo "✗ $url serves $got, not $(get_for hash "$v")" >&2; exit 1; }
  set_for url "$v" "$url"
  note "$v at $url"
done
H_P=$(get_for hash project); H_P2=$(get_for hash project-v2); H_PP=$(get_for hash project-pred); H_W=$(get_for hash wasm); H_W2=$(get_for hash wasm-v2)
U_P=$(get_for url project); U_W=$(get_for url wasm); U_W2=$(get_for url wasm-v2)

log "publish $PROJECT"
if [[ -z "$(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.project_id // empty' 2>/dev/null)" ]]; then
  out=$(call "$PARENT" create_project "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(wasm_src "$U_P" "$H_P")" '{name:$n, source:$s}')" '0.3 NEAR')
  sleep 4
fi
# project v1 active; v2, the predecessor build and the wasm build as inactive
# versions of the same project.
for v in project project-v2 project-pred wasm; do
  [[ -n "$(version_on_chain "$(get_for hash "$v")")" ]] && continue
  active=false; [[ "$v" == project ]] && active=true
  out=$(call "$PARENT" add_version "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(wasm_src "$(get_for url "$v")" "$(get_for hash "$v")")" --argjson a "$active" \
    '{project_name:$n, source:$s, set_active:$a}')" '0.1 NEAR')
  sleep 4
done
for v in project project-v2 project-pred wasm; do
  [[ "$(version_on_chain "$(get_for hash "$v")")" == "WasmUrl" ]] || { echo "✗ $(get_for hash "$v") ($v) is not a WasmUrl version of $PROJECT" >&2; exit 1; }
done
call "$PARENT" set_active_version "$(jq -nc --arg n "$PROJECT_NAME" --arg v "$H_P" '{project_name:$n, version_key:$v}')" '0 NEAR' >/dev/null
sleep 3

# ── S1 every operation ───────────────────────────────────────────────────────

log "S1 every operation of the project build, verified here"
run_src "$PARENT" "$(project_src "$H_P")" '{"operation":"all_public_keys"}'
if [[ "$RUN_OK" != "true" ]] && grep -qi "predates signing keys" <<<"$RUN_ERR"; then
  skip "the keystore predates signing keys — nothing here can be judged until it is deployed: $(head -c 200 <<<"$RUN_ERR")"
  verdict "signing keys"; exit $?
fi
if [[ "$RUN_OK" != "true" ]] && grep -qiE "outlayer:signing-keys|matching implementation was not found|unknown import" <<<"$RUN_ERR"; then
  skip "the worker predates signing keys — its linker has no outlayer:signing-keys: $(head -c 200 <<<"$RUN_ERR")"
  verdict "signing keys"; exit $?
fi
ALPHA=""; BETA=""
if ran_ok "S1 all_public_keys"; then
  remember_keys
  ALPHA=$(out_field .keys.alpha.public_key); BETA=$(out_field .keys.beta.public_key)
  [[ "$ALPHA" =~ ^[0-9a-f]{64}$ && "$BETA" =~ ^[0-9a-f]{64}$ ]] && pass "S1 all_public_keys — alpha and beta" \
    || fail "S1 all_public_keys — not two 32-byte keys: $(head -c 300 <<<"$RUN_OUT")"
fi

run_src "$PARENT" "$(project_src "$H_P")" '{"operation":"public_key","path":"alpha"}'
ran_ok "S1 public_key" && { [[ "$(out_field .public_key)" == "$ALPHA" ]] && pass "S1 public_key — alpha, as all_public_keys said" \
  || fail "S1 public_key — $(out_field .public_key) is not alpha $ALPHA"; }

MSG_HEX=$(printf 'signing keys e2e %s' "$(date +%s)" | xxd -p | tr -d '\n')
run_src "$PARENT" "$(project_src "$H_P")" "$(jq -nc --arg m "$MSG_HEX" '{operation:"sign",path:"alpha",message_hex:$m}')"
if ran_ok "S1 sign"; then
  SIG=$(out_field .signature)
  [[ "$(verify_local "$ALPHA" "$MSG_HEX" "$SIG")" == ok ]] && pass "S1 sign — the signature verifies here under alpha" \
    || fail "S1 sign — the signature does not verify here: $SIG"
  [[ "$(verify_local "$BETA" "$MSG_HEX" "$SIG")" == bad ]] && pass "S1 sign — and not under beta" || fail "S1 sign — beta verifies alpha's signature"
  [[ "$(verify_local "$ALPHA" "${MSG_HEX}00" "$SIG")" == bad ]] && pass "S1 sign — and not over another message" || fail "S1 sign — a changed message verifies"
fi

run_src "$PARENT" "$(project_src "$H_P")" "$(jq -nc --arg m "$MSG_HEX" '{operation:"sign_and_verify",path:"beta",message_hex:$m}')"
if ran_ok "S1 sign_and_verify"; then
  [[ "$(out_field .verified)/$(out_field .tampered_rejected)" == "true/true" ]] && pass "S1 sign_and_verify — verified inside the guest" \
    || fail "S1 sign_and_verify — verified=$(out_field .verified) tampered_rejected=$(out_field .tampered_rejected)"
  [[ "$(verify_local "$BETA" "$MSG_HEX" "$(out_field .signature)")" == ok ]] && pass "S1 sign_and_verify — and here" \
    || fail "S1 sign_and_verify — the signature does not verify here"
fi

run_src "$PARENT" "$(project_src "$H_P")" '{"operation":"what_i_can_see"}'
if ran_ok "S1 what_i_can_see"; then
  [[ "$(out_field .env.NEAR_USER_ACCOUNT_ID)" == "$PARENT" ]] && pass "S1 what_i_can_see — the guest reads its caller, $PARENT" \
    || fail "S1 what_i_can_see — NEAR_USER_ACCOUNT_ID is '$(out_field .env.NEAR_USER_ACCOUNT_ID)'"
  names=$(jq -r '.env | keys[]' <<<"$RUN_OUT" 2>/dev/null | grep -iE 'seed|signing|key' | tr '\n' ' ')
  [[ -z "$names" ]] && pass "S1 what_i_can_see — no environment variable is named for a key" \
    || finding "S1 what_i_can_see — environment variables named like keys: $names (S11 checks their values)"
fi

# ── S2 alpha ≠ beta ──────────────────────────────────────────────────────────

log "S2 two paths, two keys"
if [[ -n "$ALPHA" && -n "$BETA" ]]; then
  [[ "$ALPHA" != "$BETA" ]] && pass "S2 alpha ≠ beta" || fail "S2 alpha and beta are one key: $ALPHA"
else
  fail "S2 — S1 read no keys to compare"
fi

# ── S3 two callers ───────────────────────────────────────────────────────────

log "S3 another caller, another key for the same path"
run_src "$CALLER2" "$(project_src "$H_P")" '{"operation":"all_public_keys"}'
if ran_ok "S3 $CALLER2 all_public_keys"; then
  remember_keys
  OTHER_ALPHA=$(out_field .keys.alpha.public_key)
  [[ -n "$OTHER_ALPHA" && "$OTHER_ALPHA" != "$ALPHA" ]] && pass "S3 $CALLER2's alpha ≠ $PARENT's alpha" \
    || fail "S3 two callers got one alpha: $OTHER_ALPHA"
  [[ "$(out_field .keys.beta.public_key)" != "$BETA" ]] && pass "S3 $CALLER2's beta ≠ $PARENT's beta" || fail "S3 two callers got one beta"
fi

# ── S4 the same caller, again ────────────────────────────────────────────────

log "S4 the same caller, a second run"
run_src "$PARENT" "$(project_src "$H_P")" '{"operation":"all_public_keys"}'
ran_ok "S4 all_public_keys" && { [[ "$(out_field .keys.alpha.public_key)/$(out_field .keys.beta.public_key)" == "$ALPHA/$BETA" ]] \
  && pass "S4 the same keys on a second run" || fail "S4 the keys moved: $(head -c 300 <<<"$RUN_OUT")"; }

# ── S5 a second version ──────────────────────────────────────────────────────

log "S5 a second version of the project keeps its project keys"
run_src "$PARENT" "$(project_src "$H_P2")" '{"operation":"all_public_keys"}'
if ran_ok "S5 v2 all_public_keys"; then
  [[ "$(out_field .build)" == "signing-key-probe build 2" ]] && pass "S5 the v2 bytes ran ($(out_field .build))" \
    || fail "S5 the run was not v2: build '$(out_field .build)'"
  [[ "$(out_field .keys.alpha.public_key)/$(out_field .keys.beta.public_key)" == "$ALPHA/$BETA" ]] \
    && pass "S5 v2 (${H_P2:0:12}) holds v1's alpha and beta" || fail "S5 a new version got new project keys"
fi

# ── S6 wasm keys, run directly ───────────────────────────────────────────────

log "S6 the wasm build, run directly from its wasm URL"
run_src "$PARENT" "$(wasm_src "$U_W" "$H_W")" "$(jq -nc --arg m "$MSG_HEX" '{operation:"sign",path:"code",message_hex:$m}')"
CODE=""
if ran_ok "S6 direct sign"; then
  remember_keys
  CODE=$(out_field .public_key)
  [[ "$(verify_local "$CODE" "$MSG_HEX" "$(out_field .signature)")" == ok ]] && pass "S6 the code key signs, verified here" \
    || fail "S6 the code key's signature does not verify here"
fi
run_src "$PARENT" "$(wasm_src "$U_W" "$H_W")" '{"operation":"all_public_keys"}'
ran_ok "S6 direct again" && { [[ "$(out_field .keys.code.public_key)" == "$CODE" ]] && pass "S6 the same build, the same key" \
  || fail "S6 the same build gave another key"; }
run_src "$PARENT" "$(wasm_src "$U_W2" "$H_W2")" '{"operation":"all_public_keys"}'
if ran_ok "S6 wasm-v2 direct"; then
  remember_keys
  CODE2=$(out_field .keys.code.public_key)
  [[ -n "$CODE2" && "$CODE2" != "$CODE" ]] && pass "S6 another build (${H_W2:0:12}), another key" \
    || fail "S6 two builds got one code key: $CODE2"
fi
run_src "$CALLER2" "$(wasm_src "$U_W" "$H_W")" '{"operation":"all_public_keys"}'
if ran_ok "S6 $CALLER2 direct"; then
  remember_keys
  [[ "$(out_field .keys.code.public_key)" != "$CODE" ]] && pass "S6 another caller of one build, another key" \
    || fail "S6 two callers got one code key"
fi

# ── S7 bind against how the code is run ─────────────────────────────────────

log "S7 a key whose bind does not match how the code is run refuses the run"
run_src "$PARENT" "$(project_src "$H_W")" '{"operation":"all_public_keys"}'
refused_without_keys "S7 the wasm build as a project version" 'bound to the build|only to a direct run'
run_src "$PARENT" "$(wasm_src "$U_P" "$H_P")" '{"operation":"all_public_keys"}'
refused_without_keys "S7 the project build run directly" 'bound to the project|direct run with no project'

# ── S8 GitHub ────────────────────────────────────────────────────────────────

log "S8 code built from GitHub gets no keys"
github_verdict() { # github_verdict <row>
  if [[ "$RUN_OK" == "true" ]]; then
    # The platform strips a wasm32-wasip2 build with `wasm-tools strip`, which
    # drops custom sections — the manifest with them. A run then declares
    # nothing: no keys are asked for, and none may be served.
    if [[ "$(out_field .status)" == "err" ]] && grep -q "declares none" <<<"$(out_field .message)"; then
      finding "$1 — the run happened with NO keys: the platform's GitHub build dropped the outlayer.manifest section, so nothing was declared (build.sh reports this). No key was served"
    else
      fail "$1 — a GitHub-built run was served keys: $(head -c 300 <<<"$RUN_OUT")"
    fi
    return
  fi
  refused_without_keys "$1" 'GitHub|repository|not a WasmUrl version'
}
if [[ "$GITHUB_READY" != true ]]; then
  skip "S8 $GITHUB_WHY — set GITHUB_PROBE_REPO (a repository whose ROOT is wasi-examples/signing-key-probe) and a pushed GITHUB_PROBE_COMMIT"
else
  note "S8 the first run compiles $GITHUB_PROBE_REPO@${GITHUB_PROBE_COMMIT:0:12} — minutes"
  run_src "$PARENT" "$(github_src)" '{"operation":"all_public_keys"}'
  github_verdict "S8 a direct GitHub run"
  if [[ "$GITHUB_PROJECT_VERSION" == 1 ]]; then
    gkey="${GITHUB_PROBE_REPO}@${GITHUB_PROBE_COMMIT}"
    if [[ -z "$(version_on_chain "$gkey")" ]]; then
      call "$PARENT" add_version "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(github_src)" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR' >/dev/null
      sleep 4
    fi
    if [[ "$(version_on_chain "$gkey")" == "GitHub" ]]; then
      run_src "$PARENT" "$(project_src "$gkey")" '{"operation":"all_public_keys"}'
      github_verdict "S8 a project version published from GitHub"
    else
      fail "S8 the GitHub version could not be published under $PROJECT"
    fi
  else
    skip "S8 a project version from GitHub — pass GITHUB_PROJECT_VERSION=1 to publish one under $PROJECT"
  fi
fi

# ── S9 attacks ───────────────────────────────────────────────────────────────

log "S9 every attack answers with a status and a message"
run_src "$PARENT" "$(project_src "$H_P")" '{"operation":"attacks"}'
if ran_ok "S9 attacks"; then
  bad=$(jq -r '.results[] | select((.status // "") == "" or (.message // "") == "") | .name' <<<"$RUN_OUT" 2>/dev/null)
  [[ -z "$bad" ]] && pass "S9 $(jq '.results | length' <<<"$RUN_OUT") attacks, each with a status and a message" || fail "S9 without a status or message: $bad"
  unexpected=$(jq -r '.results[] | select(
      (.name == "message_at_cap" or .name == "determinism") and .status != "ok"
      or ((.name | test("^(vault_(missing|wrong)_when_declared|secp_message_not_32|nep413_wrong_type)$")) and .status != "n/a")
      or ((.name | test("^(message_at_cap|determinism|vault_missing_when_declared|vault_wrong_when_declared|secp_message_not_32|nep413_wrong_type)$") | not) and .status != "err")
    ) | "\(.name)=\(.status)"' <<<"$RUN_OUT" 2>/dev/null | tr '\n' ' ')
  [[ -z "$unexpected" ]] && pass "S9 every refusal is an err, at the cap and determinism are ok" || fail "S9 unexpected: $unexpected"
fi

# ── S10 a vault the key does not declare ────────────────────────────────────

log "S10 naming a vault for a key declared without one"
run_src "$PARENT" "$(project_src "$H_P")" '{"operation":"sign","path":"alpha","vault":"vault.attacker.testnet","message_hex":"00"}'
if [[ "$RUN_OK" == "true" ]]; then
  [[ "$(out_field .status)" == "err" ]] && grep -q "declared without a vault" <<<"$(out_field .message)" \
    && pass "S10 err: $(out_field .message | head -c 160)" || fail "S10 — answered $(out_field .status): $(out_field .message | head -c 200)"
else
  fail "S10 the run did not happen: $(head -c 200 <<<"$RUN_ERR")"
fi

# ── S12 NEP-413 ──────────────────────────────────────────────────────────────

log "S12 sign_nep413, verified here against a hash rebuilt independently"
NONCE_HEX=$(openssl rand -hex 32)
run_src "$PARENT" "$(project_src "$H_P")" "$(jq -nc --arg n "$NONCE_HEX" \
  '{operation:"sign_nep413",path:"alpha",message:"Login to signing-keys e2e",recipient:"e2e.outlayer.testnet",nonce_hex:$n}')"
if ran_ok "S12 sign_nep413"; then
  [[ "$(out_field .accountId)" == "$ALPHA" ]] && pass "S12 accountId is alpha's implicit account" || fail "S12 accountId $(out_field .accountId) is not alpha"
  want_pk=$(python3 -c "
import sys
B='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
b=bytes.fromhex(sys.argv[1]); n=int.from_bytes(b,'big'); o=''
while n: n,r=divmod(n,58); o=B[r]+o
print('ed25519:'+'1'*(len(b)-len(b.lstrip(b'\0')))+o)" "$ALPHA")
  [[ "$(out_field .publicKey)" == "$want_pk" ]] && pass "S12 publicKey is ed25519:<base58 of alpha>" || fail "S12 publicKey $(out_field .publicKey) is not $want_pk"
  sig_hex=$(out_field .signature | base64 -d 2>/dev/null | xxd -p | tr -d '\n')
  h=$(nep413_hash_local "Login to signing-keys e2e" "$NONCE_HEX" "e2e.outlayer.testnet")
  [[ "$(verify_local "$ALPHA" "$h" "$sig_hex")" == ok ]] && pass "S12 the NEP-413 signature verifies here" || fail "S12 the NEP-413 signature does not verify here"
  # The same nonce with its first hex digit changed.
  if [[ "${NONCE_HEX:0:1}" == 0 ]]; then other_nonce="1${NONCE_HEX:1}"; else other_nonce="0${NONCE_HEX:1}"; fi
  verified_tampered=""
  for label in message recipient nonce; do
    case $label in
      message)   h2=$(nep413_hash_local "Login to signing-keys e2e!" "$NONCE_HEX" "e2e.outlayer.testnet") ;;
      recipient) h2=$(nep413_hash_local "Login to signing-keys e2e" "$NONCE_HEX" "evil.testnet") ;;
      nonce)     h2=$(nep413_hash_local "Login to signing-keys e2e" "$other_nonce" "e2e.outlayer.testnet") ;;
    esac
    [[ "$(verify_local "$ALPHA" "$h2" "$sig_hex")" == bad ]] || verified_tampered+="$label "
  done
  [[ -z "$verified_tampered" ]] && pass "S12 a tampered message, recipient or nonce does not verify" \
    || fail "S12 a tampered payload verifies: $verified_tampered"
fi

# ── S22 caller predecessor ──────────────────────────────────────────────────

log "S22 a predecessor key: not the signer's; through a relay, the relay's"
PRED=""
run_src "$PARENT" "$(project_src "$H_PP")" '{"operation":"all_public_keys"}'
if ran_ok "S22 direct all_public_keys"; then
  remember_keys
  PRED=$(out_field .keys.alpha.public_key)
  [[ "$PRED" =~ ^[0-9a-f]{64}$ && "$PRED" != "$ALPHA" ]] \
    && pass "S22 on a direct call (predecessor = signer = $PARENT) the predecessor key at alpha ≠ the signer key at alpha" \
    || fail "S22 the predecessor key at alpha is '$PRED' (the signer key: $ALPHA)"
fi
run_src "$CALLER2" "$(project_src "$H_PP")" '{"operation":"all_public_keys"}'
ran_ok "S22 $CALLER2 direct all_public_keys" && { remember_keys
  [[ -n "$PRED" && "$(out_field .keys.alpha.public_key)" != "$PRED" ]] && pass "S22 another predecessor, another key" || fail "S22 two predecessors, one key"; }
if [[ "$RELAY_READY" != true ]]; then
  skip "S22 relayed through a contract — $RELAY_WHY"
else
  run_relayed "$PARENT" "$(project_src "$H_PP")" '{"operation":"what_i_can_see"}'
  ran_ok "S22 relayed what_i_can_see" && {
    [[ "$(out_field .env.NEAR_PREDECESSOR_ID)/$(out_field .env.NEAR_USER_ACCOUNT_ID)" == "$RELAY_CONTRACT/$PARENT" ]] \
      && pass "S22 the relayed run's predecessor is $RELAY_CONTRACT, its signer $PARENT" \
      || fail "S22 the relayed run sees predecessor '$(out_field .env.NEAR_PREDECESSOR_ID)', signer '$(out_field .env.NEAR_USER_ACCOUNT_ID)'"; }
  RELAYED=""
  run_relayed "$PARENT" "$(project_src "$H_PP")" '{"operation":"all_public_keys"}'
  if ran_ok "S22 relayed all_public_keys"; then
    remember_keys
    RELAYED=$(out_field .keys.alpha.public_key)
    [[ "$RELAYED" =~ ^[0-9a-f]{64}$ && "$RELAYED" != "$PRED" && "$RELAYED" != "$ALPHA" ]] \
      && pass "S22 relayed, the predecessor key is neither $PARENT's predecessor key nor its signer key" \
      || fail "S22 relayed, the predecessor key is '$RELAYED' ($PARENT's predecessor key $PRED, signer key $ALPHA)"
  fi
  run_relayed "$CALLER2" "$(project_src "$H_PP")" '{"operation":"all_public_keys"}'
  ran_ok "S22 $CALLER2 relayed all_public_keys" && { remember_keys
    [[ -n "$RELAYED" && "$(out_field .keys.alpha.public_key)" == "$RELAYED" ]] \
      && pass "S22 $CALLER2 through the same relay gets the same key: the relay contract's, whoever signs" \
      || fail "S22 two signers through one relay, two keys: $RELAYED and $(out_field .keys.alpha.public_key)"; }
  run_relayed "$PARENT" "$(project_src "$H_PP")" "$(jq -nc --arg m "$MSG_HEX" '{operation:"sign",path:"alpha",message_hex:$m}')"
  ran_ok "S22 relayed sign" && { [[ -n "$RELAYED" && "$(verify_local "$RELAYED" "$MSG_HEX" "$(out_field .signature)")" == ok ]] \
    && pass "S22 the relay's key signs, verified here" || fail "S22 the relayed signature does not verify under '$RELAYED'"; }
  run_relayed "$PARENT" "$(project_src "$H_P")" '{"operation":"all_public_keys"}'
  ran_ok "S22 relayed project build" && { [[ -n "$ALPHA" && "$(out_field .keys.alpha.public_key)" == "$ALPHA" ]] \
    && pass "S22 a signer key does not move with the relay: the project build relayed holds $PARENT's alpha" \
    || fail "S22 the project build relayed holds $(out_field .keys.alpha.public_key), not $PARENT's alpha $ALPHA"; }
fi

# ── S11 no seed anywhere ─────────────────────────────────────────────────────

log "S11 no seed in any answer of the run"
sort -u "$SEEN_KEYS" -o "$SEEN_KEYS"
if [[ ! -s "$SEEN_KEYS" ]]; then
  fail "S11 the run saw no public key to test candidates against"
else
  leak=$(python3 - "$ANSWERS" "$SEEN_KEYS" <<'PY'
import base64, re, sys
answers = open(sys.argv[1], errors="replace").read()
seen = {l.strip() for l in open(sys.argv[2]) if l.strip()}
try:
    from nacl.signing import SigningKey
    public = lambda seed: bytes(SigningKey(seed).verify_key).hex()
except ImportError:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    public = lambda seed: Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()
candidates = {bytes.fromhex(h) for h in re.findall(r'(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])', answers)}
for b64 in re.findall(r'[A-Za-z0-9+/]{43}=', answers):
    try:
        candidates.add(base64.b64decode(b64))
    except Exception:
        pass
hits = [c.hex()[:8] for c in candidates if len(c) == 32 and public(c) in seen]
print(f"{len(candidates)} {len(hits)}")
PY
)
  tried=${leak%% *}; hits=${leak##* }
  [[ "$hits" == 0 ]] && pass "S11 $tried 32-byte values in the answers tried as seeds; none derives any of the $(wc -l < "$SEEN_KEYS" | tr -d ' ') keys seen" \
    || fail "S11 $hits value(s) in the answers derive a public key the run saw — a seed left the enclave"
fi

verdict "signing keys"
