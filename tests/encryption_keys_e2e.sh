#!/usr/bin/env bash
#
# Encryption keys and raw storage end to end, on testnet:
# `wasi-examples/signing-key-probe`'s encryption builds run by a deployed
# worker against a deployed keystore and coordinator, on chain, as two callers.
#
# The builds (wasi-examples/signing-key-probe/build.sh):
#   encryption          signing alpha; encryption alpha, beta — bind project   (active version)
#   encryption-v2       the same manifest, another sha256                       (a second version)
#   encryption-storage  the encryption keys, and near:storage                   (a version; E8, E9, SC)
#   encryption-storage-pred  the same, storage_account "predecessor"            (a version; SC)
#   encryption-wasm     encryption code — bind wasm                             (direct; and as a version, E5)
#   encryption-wasm-v2  the same manifest, another sha256                       (direct)
#   encryption-pred     encryption alpha — caller predecessor, bind project     (a version; direct, E5)
#   encryption-typed    encryption alpha with a `type`                          (direct, E10)
#
# What each row pins:
#   E1  encrypt: two seals of one plaintext are two ciphertexts with two
#       nonces; the first byte is the 0x01 format marker; the length is the
#       plaintext's + 41; encrypt_and_decrypt checks the same inside the guest
#   E2  a ciphertext opened under another aad, tampered or truncated → exactly
#       `decryption failed`, in a run that succeeds; every enc_attack answers
#       as documented
#   E3  stability: the same caller opens E1's ciphertext in a later run; the
#       v2 project version opens it too (bind project survives an upgrade) and
#       its macs are v1's; the wasm build opens its own ciphertext in a later
#       run, and the wasm-v2 build (another sha256) cannot — another mac
#   E4  isolation: $CALLER2 cannot open $PARENT's ciphertext; beta cannot open
#       alpha's; the mac differs across callers and paths and is the same in
#       two runs; another caller of one wasm build has another code key
#   E5  bind must match how the code is run: the wasm build run through the
#       project, and the predecessor build (bind project) run directly →
#       refused, naming the encryption key, no key material in the answer. A
#       GitHub run declaring encryption keys → refused (needs
#       GITHUB_ENC_PROBE_REPO + GITHUB_ENC_PROBE_COMMIT; see Needs). A vault
#       key is SKIPPED: it needs a vault the project's owner holds
#   E6  caller predecessor: on a direct call the predecessor is the signer,
#       and the predecessor key at alpha is NOT the signer key at alpha (the
#       caller kind is a derivation segment); $CALLER2 gets another one.
#       Relayed through $RELAY_CONTRACT: the guest sees the relay as
#       NEAR_PREDECESSOR_ID and the signer as NEAR_USER_ACCOUNT_ID; the key is
#       neither of $PARENT's; $CALLER2 through the same relay gets the SAME
#       key — the relay contract's — and opens what $PARENT sealed through it,
#       while $PARENT's direct call cannot; the `encryption` build relayed
#       keeps the signer's alpha. Without RELAY_CONTRACT the relayed half
#       SKIPS, loudly
#   E7  no key material in any answer of the run: every 32-byte value (hex at
#       every offset, base64, byte arrays) is tried as the AEAD key and as the
#       mac subkey against every (data, mac) pair the run saw, with a local
#       HMAC; what_i_can_see names no variable after a key
#   E8  raw storage (encryption-storage): set-raw / get-raw round trip across
#       runs, bytes as given; the mode errors both ways, exactly as documented,
#       for reads and writes; raw CAS lose (current bytes handed back) and
#       win; set-if-absent-raw on an existing key → false; a refused write
#       leaves the record as it was; has / delete; list-keys shows the raw
#       name beside the encrypted one; the encrypted mode reads as before; a
#       deleted key takes the other mode; $CALLER2 neither reads nor
#       overwrites $PARENT's record; every raw_attack answers as documented
#   E9  sealed storage: sealed_put / sealed_get round trip across runs; the
#       storage key is mac(alpha, name); the stored bytes (get-raw of that
#       key) are 0x01 ‖ nonce ‖ ciphertext ‖ tag, 41 bytes longer than the
#       value, and never contain it; the name is never a stored key name; the
#       ciphertext moved under another name does not open; $CALLER2 finds
#       nothing under the name
#   E10 an encryption key that names a `type` → the run is refused before it
#       starts, naming the unknown field (the keystore's own refusal of a
#       `type` in a keyed /decrypt is pinned by its unit tests; the suite has
#       no worker token to send one)
#   SC  the storage cell (manifest `storage_account`), observed through the
#       guest. SC3, a direct call: a record encryption-storage-pred writes,
#       encryption-storage reads — one cell, the signer's. SC1, relayed through
#       $RELAY_CONTRACT with encryption-storage-pred: the record is found again
#       relayed, by $PARENT and by $CALLER2 alike, and not by $PARENT's direct
#       call — it sits in the relay contract's cell. SC2, the same relayed call
#       with encryption-storage (no field): the record is in $PARENT's cell —
#       $PARENT's direct call finds it, $CALLER2 through the relay does not.
#       With PSQL_CMD the cells are also read from storage_data. Without
#       RELAY_CONTRACT, SC1 and SC2 SKIP, loudly
#
# SKIPs loudly, whole, when the keystore or the worker predates encryption
# keys; E8 and E9 SKIP when the worker predates raw storage. A coordinator that
# predates raw storage FAILS the E8 write-mode rows (it overwrites instead of
# answering 409) — deploy the coordinator before the worker.
#
# Needs: PARENT (owns the project, first caller; key in the keychain), CALLER2
# (a second account with its key in the legacy keychain), the `outlayer` CLI
# logged in on testnet (any account: it pays for the FastFS uploads), python3,
# near, outlayer, jq, curl, shasum, xxd, cargo + wasm-tools (the build). The RPC
# is keyed through tests/lib/rpc.sh.
# For E6's relayed half, SC1 and SC2: RELAY_CONTRACT, the testnet account of
# the deployed wasi-examples/test-storage-ark/relay-contract (its `outlayer()`
# must be $CONTRACT_ID). PSQL_CMD (tests/lib/hos_common.sh) adds the SC rows'
# storage_data reads.
# For E5's GitHub row: GITHUB_ENC_PROBE_REPO + GITHUB_ENC_PROBE_COMMIT — a
# public repository whose ROOT is this probe with `default = ["encryption-wasm"]`
# in Cargo.toml (the platform builds the default features; `encryption-wasm`
# declares encryption keys only, so the refusal is the encryption family's),
# the commit pushed. GITHUB_PROJECT_VERSION=1 also publishes it as a version of
# $PROJECT. Not the signing suite's GITHUB_PROBE_REPO: its default build
# declares signing keys, and its refusal names those.
#
# Env: PROJECT_NAME (default encryption-key-probe), DEPOSIT (default 0.1 NEAR),
# ONLY=E1,E8,SC (a subset; fixtures a row needs are made on demand), OFFLINE=1
# (dry run only: no chain or GitHub reads).
#
# Money: eight FastFS uploads (~300 KB each), a project and five versions
# (0.3 + 5 × 0.1 NEAR, once), a few storage rows, and ~85 on-chain runs at
# $DEPOSIT attached (the unused part refunded — to the signer on a relayed run
# too). ~25–30 minutes.
#
# Run:
#   PARENT=you.testnet CALLER2=friend.testnet ./tests/encryption_keys_e2e.sh            # dry run: checks, no writes
#   PARENT=you.testnet CALLER2=friend.testnet ./tests/encryption_keys_e2e.sh --apply    # build, upload, publish, run
#   … GITHUB_ENC_PROBE_REPO=https://github.com/you/enc-key-probe GITHUB_ENC_PROBE_COMMIT=<sha> … --apply
#   … RELAY_CONTRACT=relay.you.testnet … --apply                                     # with the relayed rows

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

PARENT="${PARENT:-}"
CALLER2="${CALLER2:-}"
PROJECT_NAME="${PROJECT_NAME:-encryption-key-probe}"
PROJECT="$PARENT/$PROJECT_NAME"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
OFFLINE="${OFFLINE:-0}"
GITHUB_ENC_PROBE_REPO="${GITHUB_ENC_PROBE_REPO:-}"
GITHUB_ENC_PROBE_COMMIT="${GITHUB_ENC_PROBE_COMMIT:-}"
GITHUB_PROJECT_VERSION="${GITHUB_PROJECT_VERSION:-0}"
RELAY_CONTRACT="${RELAY_CONTRACT:-}"
PROBE_DIR="$REPO_ROOT/wasi-examples/signing-key-probe"
VARIANTS="$PROBE_DIR/target/variants"
BUILDS="encryption encryption-v2 encryption-storage encryption-storage-pred encryption-wasm encryption-wasm-v2 encryption-pred encryption-typed"
# The builds published as versions of $PROJECT; `encryption` is the active one.
VERSIONS="encryption encryption-v2 encryption-storage encryption-storage-pred encryption-wasm encryption-pred"
export OUTLAYER_NETWORK="$NETWORK"

# The mac subkey's label (worker/src/encryption_keys): the mac key is
# HMAC-SHA256(key, label), and a tag is HMAC-SHA256(mac key, data).
MAC_LABEL="outlayer:encryption-keys:v1:mac"

# Every answer of the run, for E7.
ANSWERS=$(mktemp -t encryption_keys_e2e.XXXXXX)
# Every (data hex, mac hex) pair the run saw, for E7.
SEEN_MACS=$(mktemp -t encryption_keys_e2e_macs.XXXXXX)
trap 'rm -f "$ANSWERS" "$SEEN_MACS"' EXIT

# ── helpers ──────────────────────────────────────────────────────────────────

want() { [[ -z "${ONLY:-}" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

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
hex_of() { printf '%s' "$1" | xxd -p | tr -d '\n'; }

# Per-build values in plain variables — the macOS bash (3.2) has no associative
# arrays. `var_name hash encryption-v2` → H_encryption_v2.
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
github_src() { jq -nc --arg r "$GITHUB_ENC_PROBE_REPO" --arg c "$GITHUB_ENC_PROBE_COMMIT" '{GitHub:{repo:$r, commit:$c, build_target:"wasm32-wasip2"}}'; }

# Shorthands: a run of one build through the project, or directly.
via_project() { run_src "$1" "$(project_src "$(get_for hash "$2")")" "$3"; }   # via_project <signer> <build> <input>
via_relay()   { run_relayed "$1" "$(project_src "$(get_for hash "$2")")" "$3"; } # via_relay <signer> <build> <input>
direct()      { run_src "$1" "$(wasm_src "$(get_for url "$2")" "$(get_for hash "$2")")" "$3"; }

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

# A run that happened and in which the host refused: status err and exactly
# this message (or, with `prefix`, a message starting with it).
answered_err() { # answered_err <row> <message> [prefix]
  if [[ "$RUN_OK" != "true" ]]; then
    fail "$1 — the run did not happen ($RUN_OK): $(head -c 300 <<<"$RUN_ERR")"; return 1
  fi
  local st msg ok=false
  st=$(out_field .status); msg=$(out_field .message)
  if [[ "$st" == err ]]; then
    if [[ "${3:-}" == prefix ]]; then [[ "$msg" == "$2"* ]] && ok=true; else [[ "$msg" == "$2" ]] && ok=true; fi
  fi
  if [[ "$ok" == true ]]; then pass "$1 — err: $(head -c 160 <<<"$msg")"; return 0; fi
  fail "$1 — answered $st: $(head -c 200 <<<"$msg") (want err \"$2\"${3:+ …})"; return 1
}

# A run that must have been refused before the module ran, carrying no key
# material and naming the rule.
refused_without_keys() { # refused_without_keys <row> <grep-pattern>
  if [[ "$RUN_OK" == "true" ]]; then
    fail "$1 — the run HAPPENED: $(head -c 300 <<<"$RUN_OUT")"; return 1
  fi
  if [[ "$RUN_OK" == "absent" ]]; then
    fail "$1 — nothing answered; a timeout is not a refusal: $RUN_ERR"; return 1
  fi
  if jq -e '[.. | objects | select(has("mac") or has("ciphertext") or has("plaintext") or has("keys") or has("public_key") or has("signature"))] | length > 0' \
       <<<"${RUN_OUT:-null}" >/dev/null 2>&1; then
    fail "$1 — refused, and yet key material came back: $(head -c 300 <<<"$RUN_OUT")"; return 1
  fi
  if ! grep -qiE "$2" <<<"$RUN_ERR"; then
    fail "$1 — refused, but not for the rule: $(head -c 300 <<<"$RUN_ERR")"; return 1
  fi
  pass "$1 — refused: $(head -c 200 <<<"$RUN_ERR")"
}

# Remember what a mac answer proves: `mac` under some key of `data`, for E7.
remember_mac() { # remember_mac <data_hex> <mac_hex>
  [[ "$2" =~ ^[0-9a-f]{64}$ ]] && printf '%s %s\n' "$1" "$2" >> "$SEEN_MACS"
}
remember_all_macs() { # every mac in an all_encryption_keys answer
  local m
  for m in $(jq -r '.keys // {} | .[] | .mac // empty' <<<"$RUN_OUT" 2>/dev/null); do
    remember_mac "$(hex_of all_encryption_keys)" "$m"
  done
}

# The hex of `hex` with one bit of byte `at` flipped (negative `at` counts
# from the end).
flip_byte() { # flip_byte <hex> <at>
  python3 -c 'import sys; b=bytearray.fromhex(sys.argv[1]); b[int(sys.argv[2])]^=1; print(b.hex())' "$1" "$2"
}

# E7's scan: every 32-byte value in <answers> — hex at every nibble offset of
# every run of 64+ hex digits, 44-character base64, 32+-number byte arrays —
# tried as the AEAD key (mac key = HMAC(c, label)) and as the mac subkey
# against every "data_hex mac_hex" line of <pairs>. Prints "<tried> <hits>
# [<kind>:<first 8 hex> …]".
scan_for_keys() { # scan_for_keys <answers> <pairs>
  python3 - "$1" "$2" "$MAC_LABEL" <<'PY'
import base64, hashlib, hmac, re, sys
text = open(sys.argv[1], errors="replace").read()
pairs = [tuple(bytes.fromhex(x) for x in l.split()) for l in open(sys.argv[2]) if len(l.split()) == 2]
label = sys.argv[3].encode()
H = lambda k, d: hmac.new(k, d, hashlib.sha256).digest()
cands = set()
for run in re.findall(r'[0-9a-fA-F]{64,}', text):
    run = run.lower()
    for i in range(0, len(run) - 63):
        cands.add(bytes.fromhex(run[i:i + 64]))
for b64 in re.findall(r'[A-Za-z0-9+/]{43}=', text):
    try:
        v = base64.b64decode(b64)
        if len(v) == 32:
            cands.add(v)
    except Exception:
        pass
for arr in re.findall(r'\[\s*(?:\d{1,3}\s*,\s*){31,}\d{1,3}\s*\]', text):
    nums = [int(n) for n in re.findall(r'\d+', arr)]
    if all(n < 256 for n in nums):
        for i in range(len(nums) - 31):
            cands.add(bytes(nums[i:i + 32]))
hits = []
for c in cands:
    sub = H(c, label)
    for data, tag in pairs:
        if H(c, data) == tag:
            hits.append("mac-subkey:" + c.hex()[:8]); break
        if H(sub, data) == tag:
            hits.append("aead-key:" + c.hex()[:8]); break
print(len(cands), len(hits), *hits)
PY
}

# ── preflight ────────────────────────────────────────────────────────────────

note "RPC: $(rpc_url_public)"
for tool in jq curl near outlayer cargo python3 shasum xxd; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
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
GITHUB_WHY="GITHUB_ENC_PROBE_REPO and GITHUB_ENC_PROBE_COMMIT are unset"
if [[ -n "$GITHUB_ENC_PROBE_REPO" && -n "$GITHUB_ENC_PROBE_COMMIT" ]]; then
  if [[ "$OFFLINE" == 1 ]]; then
    GITHUB_WHY="OFFLINE=1: $GITHUB_ENC_PROBE_REPO@${GITHUB_ENC_PROBE_COMMIT:0:12} not checked"
  else
    slug=$(sed -E 's#^https://github.com/##; s#\.git$##; s#/$##' <<<"$GITHUB_ENC_PROBE_REPO")
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://api.github.com/repos/$slug/commits/$GITHUB_ENC_PROBE_COMMIT")
    if [[ "$code" == "200" ]]; then
      GITHUB_READY=true
    else
      GITHUB_WHY="$GITHUB_ENC_PROBE_REPO@${GITHUB_ENC_PROBE_COMMIT:0:12} is not a pushed public commit (GitHub answered $code)"
    fi
  fi
fi

# E6's relayed half, SC1 and SC2 need the relay deployed, relaying to this
# contract. A relay named but unusable stops --apply: the rows it was named for
# would not run.
RELAY_READY=false
if [[ -z "$RELAY_CONTRACT" ]]; then
  RELAY_WHY="RELAY_CONTRACT is unset — deploy wasi-examples/test-storage-ark/relay-contract (its README) and export its account"
elif [[ "$OFFLINE" == 1 && "$APPLY" != true ]]; then
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
  # The E7 scanner against the keystore's pinned key (worker/tests/
  # encryption_key_probe.rs): planted at an odd offset in a longer hex run it
  # is found as the AEAD key, its mac subkey in base64 is found as the subkey,
  # and a clean transcript yields nothing.
  st_dir=$(mktemp -d -t encryption_keys_e2e_selftest.XXXXXX)
  key_a=4324b148cb409d9a56e27a37c0cfbc4787481db4dec90cfcd2219a091c4a5d0a
  printf '%s %s\n' "$(hex_of "alice's inbox")" 51f41e345c29ef105e29b11df910df64ee85f36bf767d08c71ae9474ee3a7b2b > "$st_dir/pairs"
  sub_b64=$(python3 -c 'import hmac,hashlib,base64,sys; print(base64.b64encode(hmac.new(bytes.fromhex(sys.argv[1]), sys.argv[2].encode(), hashlib.sha256).digest()).decode())' "$key_a" "$MAC_LABEL")
  printf '{"ciphertext":"01ab%s77"} {"x":"%s"}\n' "$key_a" "$sub_b64" > "$st_dir/planted"
  printf '{"mac":"51f41e345c29ef105e29b11df910df64ee85f36bf767d08c71ae9474ee3a7b2b","ciphertext":"01%s"}\n' "$(openssl rand -hex 60)" > "$st_dir/clean"
  planted=$(scan_for_keys "$st_dir/planted" "$st_dir/pairs"); clean=$(scan_for_keys "$st_dir/clean" "$st_dir/pairs")
  rm -rf "$st_dir"
  if [[ "$planted" == *aead-key:4324b148* && "$planted" == *mac-subkey:* && "$(cut -d' ' -f2 <<<"$clean")" == 0 ]]; then
    pass "E7 scanner self-test — a planted key and mac subkey are found ($(cut -d' ' -f1-2 <<<"$planted")), a clean answer yields none"
  else
    fail "E7 scanner self-test — planted: '$planted', clean: '$clean'"
  fi
  if [[ "$OFFLINE" == 1 ]]; then
    note "OFFLINE=1: the project and its versions are not read from the chain"
  else
    note "project: $PROJECT ($(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r 'if .project_id then "on chain, active " + .active_version else "not on chain yet" end' 2>/dev/null || echo 'unreadable'))"
  fi
  for v in $BUILDS; do
    f="$VARIANTS/signing-key-probe-$v.wasm"
    if [[ -f "$f" ]]; then
      h=$(sha_of "$f")
      if [[ "$OFFLINE" == 1 ]]; then kind="(not read)"; else kind=$(version_on_chain "$h"); fi
      case " $VERSIONS " in *" $v "*) note "$v: built locally, sha256 $h; as a version of $PROJECT: ${kind:-absent}" ;;
                            *) note "$v: built locally, sha256 $h; run directly" ;; esac
    else
      note "$v: not built yet (--apply runs $PROBE_DIR/build.sh)"
    fi
  done
  if [[ "$GITHUB_READY" == true ]]; then note "E5 GitHub: $GITHUB_ENC_PROBE_REPO@${GITHUB_ENC_PROBE_COMMIT:0:12} is pushed"; else warn "E5 GitHub will SKIP: $GITHUB_WHY"; fi
  if [[ "$RELAY_READY" == true ]]; then note "E6 relayed, SC1, SC2: $RELAY_CONTRACT relays to $CONTRACT_ID"; else warn "E6 relayed half, SC1 and SC2 will SKIP: $RELAY_WHY"; fi
  [[ -n "${ONLY:-}" ]] && note "ONLY=$ONLY"
  echo "  Pass --apply to run." >&2
  verdict "encryption keys (dry run)"; exit $?
fi

# ── setup: build, upload, publish ────────────────────────────────────────────

log "build the probe"
(cd "$PROBE_DIR" && ./build.sh >/dev/null) || { echo "✗ $PROBE_DIR/build.sh failed" >&2; exit 1; }
for v in $BUILDS; do
  set_for hash "$v" "$(sha_of "$VARIANTS/signing-key-probe-$v.wasm")"
  note "$v sha256 $(get_for hash "$v")"
done

log "upload to FastFS"
for v in $BUILDS; do
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

log "publish $PROJECT"
if [[ -z "$(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.project_id // empty' 2>/dev/null)" ]]; then
  call "$PARENT" create_project "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(wasm_src "$(get_for url encryption)" "$(get_for hash encryption)")" '{name:$n, source:$s}')" '0.3 NEAR' >/dev/null
  sleep 4
fi
for v in $VERSIONS; do
  [[ -n "$(version_on_chain "$(get_for hash "$v")")" ]] && continue
  active=false; [[ "$v" == encryption ]] && active=true
  call "$PARENT" add_version "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(wasm_src "$(get_for url "$v")" "$(get_for hash "$v")")" --argjson a "$active" \
    '{project_name:$n, source:$s, set_active:$a}')" '0.1 NEAR' >/dev/null
  sleep 4
done
for v in $VERSIONS; do
  [[ "$(version_on_chain "$(get_for hash "$v")")" == "WasmUrl" ]] || { echo "✗ $(get_for hash "$v") ($v) is not a WasmUrl version of $PROJECT" >&2; exit 1; }
done
call "$PARENT" set_active_version "$(jq -nc --arg n "$PROJECT_NAME" --arg v "$(get_for hash encryption)" '{project_name:$n, version_key:$v}')" '0 NEAR' >/dev/null
sleep 3

TAG="e2e-$(date +%s)"
PT="encryption keys e2e $TAG"; PT_HEX=$(hex_of "$PT")
AAD_HEX=$(hex_of "row/$TAG")
KNOWN_HEX=$(hex_of "a record name $TAG")

# ── the gate, and the fixtures later rows share ─────────────────────────────

log "gate: every declared encryption key answers on the encryption build"
via_project "$PARENT" encryption '{"operation":"all_encryption_keys"}'
if [[ "$RUN_OK" != "true" ]] && grep -qi "predates encryption keys" <<<"$RUN_ERR"; then
  skip "the keystore predates encryption keys — nothing here can be judged until it is deployed: $(head -c 200 <<<"$RUN_ERR")"
  verdict "encryption keys"; exit $?
fi
if [[ "$RUN_OK" != "true" ]] && grep -qiE "outlayer:encryption-keys|matching implementation was not found|unknown import" <<<"$RUN_ERR"; then
  skip "the worker predates encryption keys — its linker has no outlayer:encryption-keys: $(head -c 200 <<<"$RUN_ERR")"
  verdict "encryption keys"; exit $?
fi
MAC_ALPHA=""; MAC_BETA=""
if ran_ok "gate all_encryption_keys"; then
  remember_all_macs
  MAC_ALPHA=$(out_field .keys.alpha.mac); MAC_BETA=$(out_field .keys.beta.mac)
  [[ "$MAC_ALPHA" =~ ^[0-9a-f]{64}$ && "$MAC_BETA" =~ ^[0-9a-f]{64}$ ]] && pass "gate — alpha and beta each answer a 32-byte mac" \
    || fail "gate — not two 32-byte macs: $(head -c 300 <<<"$RUN_OUT")"
fi

# E1's first ciphertext, sealed on demand for any row that opens it.
CT1=""
ensure_ct1() {
  [[ -n "$CT1" ]] && return 0
  via_project "$PARENT" encryption "$(jq -nc --arg p "$PT_HEX" --arg a "$AAD_HEX" '{operation:"encrypt",path:"alpha",plaintext_hex:$p,aad_hex:$a}')"
  ran_ok "E1 encrypt" && CT1=$(out_field .ciphertext)
  [[ -n "$CT1" ]]
}

# The code key's mac of the wasm build, run directly by $PARENT.
CODE_MAC=""
ensure_code_mac() {
  [[ -n "$CODE_MAC" ]] && return 0
  direct "$PARENT" encryption-wasm '{"operation":"all_encryption_keys"}'
  ran_ok "E3 wasm all_encryption_keys" && { remember_all_macs; CODE_MAC=$(out_field .keys.code.mac); }
  [[ -n "$CODE_MAC" ]]
}

# ── E1 encrypt ───────────────────────────────────────────────────────────────

if want E1; then
  log "E1 encrypt: format, length, a fresh nonce per seal"
  if ensure_ct1; then
    [[ "${CT1:0:2}" == 01 ]] && pass "E1 the first byte is the 0x01 format marker" || fail "E1 the first byte is ${CT1:0:2}"
    (( ${#CT1} / 2 == ${#PT_HEX} / 2 + 41 )) && pass "E1 $(( ${#CT1} / 2 )) bytes: the plaintext's $(( ${#PT_HEX} / 2 )) + 41" \
      || fail "E1 $(( ${#CT1} / 2 )) bytes for a $(( ${#PT_HEX} / 2 ))-byte plaintext"
    [[ "$CT1" != *"$PT_HEX"* ]] && pass "E1 the plaintext is not in the ciphertext" || fail "E1 the plaintext is IN the ciphertext"
    via_project "$PARENT" encryption "$(jq -nc --arg p "$PT_HEX" --arg a "$AAD_HEX" '{operation:"encrypt",path:"alpha",plaintext_hex:$p,aad_hex:$a}')"
    if ran_ok "E1 a second encrypt"; then
      CT1B=$(out_field .ciphertext)
      [[ -n "$CT1B" && "$CT1B" != "$CT1" ]] && pass "E1 one plaintext sealed twice: two ciphertexts" || fail "E1 two seals gave one ciphertext"
      [[ "${CT1B:2:48}" != "${CT1:2:48}" ]] && pass "E1 and two nonces" || fail "E1 two seals share a nonce: ${CT1:2:48}"
    fi
  fi
  via_project "$PARENT" encryption "$(jq -nc --arg p "$PT_HEX" --arg a "$AAD_HEX" '{operation:"encrypt_and_decrypt",path:"beta",plaintext_hex:$p,aad_hex:$a}')"
  ran_ok "E1 encrypt_and_decrypt" && {
    [[ "$(out_field '[.round_trip,.fresh_nonce,.other_aad_refused,.length,.format] | all')" == true ]] \
      && pass "E1 encrypt_and_decrypt — round trip, fresh nonce, another aad refused, length and format, inside the guest" \
      || fail "E1 encrypt_and_decrypt — $(head -c 300 <<<"$RUN_OUT")"; }
fi

# ── E2 failures to open ──────────────────────────────────────────────────────

if want E2; then
  log "E2 another aad, a tampered or truncated ciphertext: decryption failed"
  if ensure_ct1; then
    via_project "$PARENT" encryption "$(jq -nc --arg c "$CT1" --arg a "$(hex_of "row/another")" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E2 another aad" "decryption failed"
    via_project "$PARENT" encryption "$(jq -nc --arg c "$(flip_byte "$CT1" -1)" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E2 a changed tag" "decryption failed"
    via_project "$PARENT" encryption "$(jq -nc --arg c "${CT1:0:${#CT1}-2}" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E2 a truncated ciphertext" "decryption failed"
  fi
  via_project "$PARENT" encryption '{"operation":"enc_attacks"}'
  if ran_ok "E2 enc_attacks"; then
    bad=$(jq -r '.results[] | select((.status // "") == "" or (.message // "") == "") | .name' <<<"$RUN_OUT" 2>/dev/null)
    [[ -z "$bad" ]] && pass "E2 $(jq '.results | length' <<<"$RUN_OUT") enc_attacks, each with a status and a message" || fail "E2 without a status or message: $bad"
    # The encryption build: no vaulted key, and every signing path is also an
    # encryption path (the host tests pin the same table).
    unexpected=$(jq -r '.results[] | select(
        ((.name | test("^(plaintext_at_cap|mac_determinism|mac_separation)$")) and .status != "ok")
        or ((.name | test("^(vault_missing_when_declared|vault_wrong_when_declared|signing_path_is_not_an_encryption_path)$")) and .status != "n/a")
        or ((.name | test("^(plaintext_at_cap|mac_determinism|mac_separation|vault_missing_when_declared|vault_wrong_when_declared|signing_path_is_not_an_encryption_path)$") | not) and .status != "err")
        or ((.name | test("^(wrong_aad|tampered_tag|tampered_body|tampered_nonce|bad_format_marker|truncated|shorter_than_overhead|empty_ciphertext|cross_path)$")) and .message != "decryption failed")
      ) | "\(.name)=\(.status)"' <<<"$RUN_OUT" 2>/dev/null | tr '\n' ' ')
    [[ -z "$unexpected" ]] && pass "E2 every failure to open is exactly \"decryption failed\", every refusal an err; at the cap and the mac checks ok" \
      || fail "E2 unexpected: $unexpected"
  fi
fi

# ── E3 stability ─────────────────────────────────────────────────────────────

if want E3; then
  log "E3 the same key in a later run, in a second version; a new wasm build has a new key"
  if ensure_ct1; then
    via_project "$PARENT" encryption "$(jq -nc --arg c "$CT1" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    ran_ok "E3 decrypt in a later run" && { [[ "$(out_field .plaintext)" == "$PT_HEX" ]] \
      && pass "E3 sealed in one run, opened in a later one by the same caller" || fail "E3 opened to $(out_field .plaintext), not the plaintext"; }
    via_project "$PARENT" encryption-v2 "$(jq -nc --arg c "$CT1" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    if ran_ok "E3 v2 decrypt"; then
      [[ "$(out_field .build)" == "signing-key-probe build 2" ]] && pass "E3 the v2 bytes ran ($(out_field .build))" || fail "E3 the run was not v2: build '$(out_field .build)'"
      [[ "$(out_field .plaintext)" == "$PT_HEX" ]] && pass "E3 v2 ($(get_for hash encryption-v2 | head -c 12)) opens what v1 sealed" \
        || fail "E3 v2 could not open v1's ciphertext: $(out_field .message)"
    fi
  fi
  via_project "$PARENT" encryption-v2 '{"operation":"all_encryption_keys"}'
  ran_ok "E3 v2 all_encryption_keys" && { remember_all_macs; [[ "$(out_field .keys.alpha.mac)/$(out_field .keys.beta.mac)" == "$MAC_ALPHA/$MAC_BETA" ]] \
    && pass "E3 v2's alpha and beta macs are v1's" || fail "E3 a new version got new keys: $(head -c 300 <<<"$RUN_OUT")"; }

  direct "$PARENT" encryption-wasm "$(jq -nc --arg p "$PT_HEX" --arg a "$AAD_HEX" '{operation:"encrypt",path:"code",plaintext_hex:$p,aad_hex:$a}')"
  CTW=""
  ran_ok "E3 wasm encrypt" && CTW=$(out_field .ciphertext)
  if [[ -n "$CTW" ]]; then
    direct "$PARENT" encryption-wasm "$(jq -nc --arg c "$CTW" --arg a "$AAD_HEX" '{operation:"decrypt",path:"code",ciphertext_hex:$c,aad_hex:$a}')"
    ran_ok "E3 wasm decrypt" && { [[ "$(out_field .plaintext)" == "$PT_HEX" ]] \
      && pass "E3 the wasm build opens its own ciphertext in a later run" || fail "E3 the wasm build could not open its own ciphertext"; }
    direct "$PARENT" encryption-wasm-v2 "$(jq -nc --arg c "$CTW" --arg a "$AAD_HEX" '{operation:"decrypt",path:"code",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E3 another build ($(get_for hash encryption-wasm-v2 | head -c 12)) cannot open the first build's ciphertext" "decryption failed"
  fi
  if ensure_code_mac; then
    direct "$PARENT" encryption-wasm-v2 '{"operation":"all_encryption_keys"}'
    ran_ok "E3 wasm-v2 all_encryption_keys" && { remember_all_macs; [[ "$(out_field .keys.code.mac)" != "$CODE_MAC" ]] \
      && pass "E3 another build, another code key (its mac differs)" || fail "E3 two builds, one code mac: $CODE_MAC"; }
  fi
fi

# ── E4 isolation ─────────────────────────────────────────────────────────────

if want E4; then
  log "E4 another caller, another path: another key"
  if ensure_ct1; then
    via_project "$CALLER2" encryption "$(jq -nc --arg c "$CT1" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E4 $CALLER2 cannot open $PARENT's ciphertext" "decryption failed"
    via_project "$PARENT" encryption "$(jq -nc --arg c "$CT1" --arg a "$AAD_HEX" '{operation:"decrypt",path:"beta",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E4 beta cannot open alpha's ciphertext" "decryption failed"
  fi
  [[ -n "$MAC_ALPHA" && "$MAC_ALPHA" != "$MAC_BETA" ]] && pass "E4 alpha's mac ≠ beta's" || fail "E4 alpha and beta: one mac ($MAC_ALPHA)"
  via_project "$CALLER2" encryption '{"operation":"all_encryption_keys"}'
  ran_ok "E4 $CALLER2 all_encryption_keys" && { remember_all_macs
    [[ "$(out_field .keys.alpha.mac)" != "$MAC_ALPHA" && "$(out_field .keys.beta.mac)" != "$MAC_BETA" ]] \
      && pass "E4 $CALLER2's alpha and beta macs ≠ $PARENT's" || fail "E4 two callers share a mac: $(head -c 300 <<<"$RUN_OUT")"; }
  M1=""
  via_project "$PARENT" encryption "$(jq -nc --arg d "$KNOWN_HEX" '{operation:"mac",path:"alpha",plaintext_hex:$d}')"
  ran_ok "E4 mac" && { M1=$(out_field .mac); remember_mac "$KNOWN_HEX" "$M1"; }
  via_project "$PARENT" encryption "$(jq -nc --arg d "$KNOWN_HEX" '{operation:"mac",path:"alpha",plaintext_hex:$d}')"
  ran_ok "E4 mac again" && { [[ -n "$M1" && "$(out_field .mac)" == "$M1" ]] && pass "E4 one name, one mac, in two runs" || fail "E4 the mac moved: $M1 → $(out_field .mac)"; }
  via_project "$CALLER2" encryption "$(jq -nc --arg d "$KNOWN_HEX" '{operation:"mac",path:"alpha",plaintext_hex:$d}')"
  ran_ok "E4 $CALLER2 mac" && { remember_mac "$KNOWN_HEX" "$(out_field .mac)"
    [[ "$(out_field .mac)" != "$M1" ]] && pass "E4 one name, another caller: another mac" || fail "E4 two callers, one mac of one name"; }
  if ensure_code_mac; then
    direct "$CALLER2" encryption-wasm '{"operation":"all_encryption_keys"}'
    ran_ok "E4 $CALLER2 wasm all_encryption_keys" && { remember_all_macs
      [[ "$(out_field .keys.code.mac)" != "$CODE_MAC" ]] && pass "E4 another caller of one wasm build, another code key" \
        || fail "E4 two callers of one build share the code mac"; }
  fi
fi

# ── E5 bind against how the code is run ─────────────────────────────────────

if want E5; then
  log "E5 a key whose bind does not match how the code is run refuses the run"
  via_project "$PARENT" encryption-wasm '{"operation":"all_encryption_keys"}'
  refused_without_keys "E5 the wasm build as a project version" 'encryption key .*bound to the build'
  direct "$PARENT" encryption-pred '{"operation":"all_encryption_keys"}'
  refused_without_keys "E5 a project-bound build run directly" 'encryption key .*bound to the project'
  skip "E5 a vault key — the encryption-vault build names vault.alice.near; a live run needs a vault owned by the project's owner ($PARENT), and the vault rules are pinned by worker/tests/encryption_key_probe.rs and the keystore's unit tests"

  github_verdict() { # github_verdict <row>
    if [[ "$RUN_OK" == "true" ]]; then
      if [[ "$(out_field .status)" == "err" ]] && grep -qiE "no encryption key|declares none" <<<"$(out_field .message)"; then
        finding "$1 — the run happened with NO keys: the GitHub build dropped the outlayer.manifest section, so nothing was declared. No key was served"
      else
        fail "$1 — a GitHub-built run was served encryption keys: $(head -c 300 <<<"$RUN_OUT")"
      fi
      return
    fi
    refused_without_keys "$1" 'gets no encryption keys'
  }
  if [[ "$GITHUB_READY" != true ]]; then
    skip "E5 GitHub — $GITHUB_WHY; set GITHUB_ENC_PROBE_REPO (a repository whose ROOT is this probe, default feature encryption-wasm) and a pushed GITHUB_ENC_PROBE_COMMIT"
  else
    note "E5 the first GitHub run compiles $GITHUB_ENC_PROBE_REPO@${GITHUB_ENC_PROBE_COMMIT:0:12} — minutes"
    run_src "$PARENT" "$(github_src)" '{"operation":"all_encryption_keys"}'
    github_verdict "E5 a direct GitHub run"
    if [[ "$GITHUB_PROJECT_VERSION" == 1 ]]; then
      gkey="${GITHUB_ENC_PROBE_REPO}@${GITHUB_ENC_PROBE_COMMIT}"
      if [[ -z "$(version_on_chain "$gkey")" ]]; then
        call "$PARENT" add_version "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(github_src)" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR' >/dev/null
        sleep 4
      fi
      if [[ "$(version_on_chain "$gkey")" == "GitHub" ]]; then
        run_src "$PARENT" "$(project_src "$gkey")" '{"operation":"all_encryption_keys"}'
        github_verdict "E5 a project version published from GitHub"
      else
        fail "E5 the GitHub version could not be published under $PROJECT"
      fi
    else
      skip "E5 a project version from GitHub — pass GITHUB_PROJECT_VERSION=1 to publish one under $PROJECT"
    fi
  fi
fi

# ── E6 caller predecessor ────────────────────────────────────────────────────

if want E6; then
  log "E6 a predecessor key: not the signer key, even when the accounts are one"
  PRED_MAC=""
  via_project "$PARENT" encryption-pred '{"operation":"all_encryption_keys"}'
  if ran_ok "E6 predecessor all_encryption_keys"; then
    remember_all_macs
    PRED_MAC=$(out_field .keys.alpha.mac)
    [[ "$PRED_MAC" =~ ^[0-9a-f]{64}$ && "$PRED_MAC" != "$MAC_ALPHA" ]] \
      && pass "E6 on a direct call (predecessor = signer = $PARENT) the predecessor key at alpha ≠ the signer key at alpha" \
      || fail "E6 the predecessor key at alpha is the signer key ($PRED_MAC)"
  fi
  via_project "$CALLER2" encryption-pred '{"operation":"all_encryption_keys"}'
  ran_ok "E6 $CALLER2 predecessor all_encryption_keys" && { remember_all_macs
    [[ -n "$PRED_MAC" && "$(out_field .keys.alpha.mac)" != "$PRED_MAC" ]] && pass "E6 another predecessor, another key" || fail "E6 two predecessors, one key"; }
  if [[ "$RELAY_READY" != true ]]; then
    skip "E6 relayed through a contract — $RELAY_WHY"
  else
    via_relay "$PARENT" encryption-pred '{"operation":"what_i_can_see"}'
    ran_ok "E6 relayed what_i_can_see" && {
      [[ "$(out_field .env.NEAR_PREDECESSOR_ID)/$(out_field .env.NEAR_USER_ACCOUNT_ID)" == "$RELAY_CONTRACT/$PARENT" ]] \
        && pass "E6 the relayed run's predecessor is $RELAY_CONTRACT, its signer $PARENT" \
        || fail "E6 the relayed run sees predecessor '$(out_field .env.NEAR_PREDECESSOR_ID)', signer '$(out_field .env.NEAR_USER_ACCOUNT_ID)'"; }
    RELAYED_MAC=""
    via_relay "$PARENT" encryption-pred '{"operation":"all_encryption_keys"}'
    if ran_ok "E6 relayed all_encryption_keys"; then
      remember_all_macs
      RELAYED_MAC=$(out_field .keys.alpha.mac)
      [[ "$RELAYED_MAC" =~ ^[0-9a-f]{64}$ && "$RELAYED_MAC" != "$PRED_MAC" && "$RELAYED_MAC" != "$MAC_ALPHA" ]] \
        && pass "E6 relayed, the predecessor key is neither $PARENT's predecessor key nor its signer key" \
        || fail "E6 relayed, alpha's mac is '$RELAYED_MAC' ($PARENT's predecessor mac $PRED_MAC, signer mac $MAC_ALPHA)"
    fi
    via_relay "$CALLER2" encryption-pred '{"operation":"all_encryption_keys"}'
    ran_ok "E6 $CALLER2 relayed all_encryption_keys" && { remember_all_macs
      [[ -n "$RELAYED_MAC" && "$(out_field .keys.alpha.mac)" == "$RELAYED_MAC" ]] \
        && pass "E6 $CALLER2 through the same relay gets the same key: the relay contract's, whoever signs" \
        || fail "E6 two signers through one relay, two keys: $RELAYED_MAC and $(out_field .keys.alpha.mac)"; }
    CTR=""
    via_relay "$PARENT" encryption-pred "$(jq -nc --arg p "$PT_HEX" --arg a "$AAD_HEX" '{operation:"encrypt",path:"alpha",plaintext_hex:$p,aad_hex:$a}')"
    ran_ok "E6 relayed encrypt" && CTR=$(out_field .ciphertext)
    if [[ -n "$CTR" ]]; then
      via_relay "$CALLER2" encryption-pred "$(jq -nc --arg c "$CTR" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
      ran_ok "E6 $CALLER2 relayed decrypt" && { [[ "$(out_field .plaintext)" == "$PT_HEX" ]] \
        && pass "E6 what $PARENT sealed through the relay, $CALLER2 opens through it" || fail "E6 $CALLER2 through the relay opened to '$(out_field .plaintext)'"; }
      via_project "$PARENT" encryption-pred "$(jq -nc --arg c "$CTR" --arg a "$AAD_HEX" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
      answered_err "E6 $PARENT's direct call cannot open what it sealed through the relay" "decryption failed"
    fi
    via_relay "$PARENT" encryption '{"operation":"all_encryption_keys"}'
    ran_ok "E6 relayed encryption build" && { remember_all_macs
      [[ -n "$MAC_ALPHA" && "$(out_field .keys.alpha.mac)" == "$MAC_ALPHA" ]] \
        && pass "E6 a signer key does not move with the relay: the encryption build relayed holds $PARENT's alpha" \
        || fail "E6 the encryption build relayed holds alpha mac $(out_field .keys.alpha.mac), not $PARENT's $MAC_ALPHA"; }
  fi
fi

# ── E8 raw storage ───────────────────────────────────────────────────────────

STORAGE_READY=""
storage_gate() { # storage_gate — 0 when the worker serves raw storage; the first call decides
  [[ -n "$STORAGE_READY" ]] && { [[ "$STORAGE_READY" == yes ]]; return; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$TAG/gate" '{operation:"storage_has",key:$k}')"
  if [[ "$RUN_OK" != "true" ]] && grep -qi "storage is not configured" <<<"$RUN_ERR"; then
    STORAGE_READY=no
    fail "E8/E9 a project run of the storage build got no storage from the worker: $(head -c 200 <<<"$RUN_ERR")"
    return 1
  fi
  if [[ "$RUN_OK" != "true" ]] && grep -qiE "set-raw|get-raw|matching implementation was not found" <<<"$RUN_ERR"; then
    STORAGE_READY=no
    skip "E8/E9 the worker predates raw storage — its linker has no near:storage set-raw/get-raw: $(head -c 200 <<<"$RUN_ERR")"
    return 1
  fi
  STORAGE_READY=yes
}

if want E8 && storage_gate; then
  log "E8 raw storage"
  K1="$TAG/raw"; K2="$TAG/enc"
  V1=00ff10ab; V2=$(hex_of "encrypted $TAG"); V3=c0ffee; V4=0404
  MODE_HINT="(a coordinator that predates raw storage overwrites instead of answering 409 — no raw-storage build may run before the new coordinator is live)"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" --arg v "$V1" '{operation:"raw_set",key:$k,value_hex:$v}')"
  ran_ok "E8 raw_set" && pass "E8 raw_set $K1"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"raw_get",key:$k}')"
  ran_ok "E8 raw_get" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/$V1" ]] \
    && pass "E8 raw_get in a later run: the bytes as given" || fail "E8 raw_get answered found=$(out_field .found) $(out_field .value_hex), not $V1"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K2" --arg v "$V2" '{operation:"enc_set",key:$k,value_hex:$v}')"
  ran_ok "E8 enc_set" && pass "E8 enc_set $K2 (an encrypted record beside it)"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K2" '{operation:"enc_get",key:$k}')"
  ran_ok "E8 enc_get" && { [[ "$(out_field .value_hex)" == "$V2" ]] \
    && pass "E8 the encrypted mode reads as before beside raw records" || fail "E8 enc_get answered $(out_field .value_hex), not $V2"; }

  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K2" '{operation:"raw_get",key:$k}')"
  answered_err "E8 get-raw on an encrypted record" "the record at this key was written encrypted; read it with get"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"enc_get",key:$k}')"
  answered_err "E8 get on a raw record" "the record at this key was written raw; read it with get-raw"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K2" '{operation:"raw_set",key:$k,value_hex:"00"}')"
  answered_err "E8 set-raw over an encrypted record" "the record at this key was written encrypted; set-raw does not convert it — write it with set, or delete it first" \
    || note "$MODE_HINT"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"enc_set",key:$k,value_hex:"00"}')"
  answered_err "E8 set over a raw record" "the record at this key was written raw; set does not convert it — write it with set-raw, or delete it first" \
    || note "$MODE_HINT"

  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" --arg n "$V3" '{operation:"raw_set_if_equals",key:$k,expected_hex:"dead",new_hex:$n}')"
  ran_ok "E8 raw CAS with stale bytes" && { [[ "$(out_field .updated)/$(out_field .current_hex)" == "false/$V1" ]] \
    && pass "E8 raw CAS with stale bytes loses and hands back the stored bytes" || fail "E8 raw CAS lose: updated=$(out_field .updated) current=$(out_field .current_hex)"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" --arg e "$V1" --arg n "$V3" '{operation:"raw_set_if_equals",key:$k,expected_hex:$e,new_hex:$n}')"
  ran_ok "E8 raw CAS with the stored bytes" && { [[ "$(out_field .updated)" == true ]] \
    && pass "E8 raw CAS with the stored bytes wins" || fail "E8 raw CAS win: updated=$(out_field .updated) current=$(out_field .current_hex)"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" --arg v "$V4" '{operation:"raw_set_if_absent",key:$k,value_hex:$v}')"
  ran_ok "E8 set-if-absent-raw on an existing key" && { [[ "$(out_field .inserted)" == false ]] \
    && pass "E8 set-if-absent-raw on an existing key → not inserted" || fail "E8 set-if-absent-raw inserted over $K1"; }

  via_project "$CALLER2" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"raw_get",key:$k}')"
  ran_ok "E8 $CALLER2 raw_get" && { [[ "$(out_field .found)" == false ]] \
    && pass "E8 $CALLER2 does not see $PARENT's raw record" || fail "E8 $CALLER2 read $PARENT's raw record: $(out_field .value_hex)"; }
  via_project "$CALLER2" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"raw_set_if_absent",key:$k,value_hex:"cc"}')"
  ran_ok "E8 $CALLER2 raw_set_if_absent" && { [[ "$(out_field .inserted)" == true ]] \
    && pass "E8 $CALLER2 writes the same name into its own storage" || fail "E8 $CALLER2's write found a record: $(head -c 200 <<<"$RUN_OUT")"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"raw_get",key:$k}')"
  ran_ok "E8 raw_get after" && { [[ "$(out_field .value_hex)" == "$V3" ]] \
    && pass "E8 $K1 holds the CAS winner: the refused writes, set-if-absent and $CALLER2 left it alone" \
    || fail "E8 $K1 holds $(out_field .value_hex), not $V3"; }
  via_project "$CALLER2" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"storage_delete",key:$k}')"
  ran_ok "E8 $CALLER2 cleanup" >/dev/null || true

  via_project "$PARENT" encryption-storage "$(jq -nc --arg p "$TAG/" '{operation:"storage_list",prefix:$p}')"
  ran_ok "E8 storage_list" && { got=$(out_field '.keys | sort | join(",")')
    [[ "$got" == "$K2,$K1" ]] && pass "E8 list-keys: the raw name as written beside the encrypted one ($got)" || fail "E8 list-keys under $TAG/: $got"; }

  via_project "$PARENT" encryption-storage "$(jq -nc --arg p "$TAG/attacks" '{operation:"raw_attacks",key:$p}')"
  if ran_ok "E8 raw_attacks"; then
    unexpected=$(jq -r '.results[] | select(
        ((.name | test("^(cas_raw_win|delete_raw|list_shows_raw_name)$")) and .status != "ok")
        or ((.name | test("^(cas_raw_win|delete_raw|list_shows_raw_name)$") | not) and .status != "err")
        or (has("unchanged") and .unchanged != true)
        or (has("current_is_stored") and .current_is_stored != true)
        or (.name == "get_raw_on_encrypted" and .message != "the record at this key was written encrypted; read it with get")
        or (.name == "get_on_raw" and .message != "the record at this key was written raw; read it with get-raw")
        or (.name == "set_raw_over_encrypted" and (.message | startswith("the record at this key was written encrypted; set-raw does not convert it") | not))
        or (.name == "set_over_raw" and (.message | startswith("the record at this key was written raw; set does not convert it") | not))
        or (.name == "cas_raw_on_encrypted" and .message != "the record at this key was written encrypted; compare it with set-if-equals")
        or (.name == "cas_on_raw" and .message != "the record at this key was written raw; compare it with set-if-equals-raw")
      ) | "\(.name)=\(.status): \(.message | .[0:80])"' <<<"$RUN_OUT" 2>/dev/null)
    [[ -z "$unexpected" ]] && pass "E8 $(jq '.results | length' <<<"$RUN_OUT") raw_attacks as documented: mode errors both ways, refused writes change nothing, CAS lose/win/absent" \
      || fail "E8 raw_attacks unexpected: $(tr '\n' ';' <<<"$unexpected") $MODE_HINT"
  fi

  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"storage_delete",key:$k}')"
  ran_ok "E8 delete" && { [[ "$(out_field .deleted)" == true ]] && pass "E8 delete $K1" || fail "E8 delete answered $(out_field .deleted)"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"storage_has",key:$k}')"
  ran_ok "E8 has after delete" && { [[ "$(out_field .exists)" == false ]] && pass "E8 has after delete → false" || fail "E8 $K1 still exists"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"enc_set",key:$k,value_hex:"01"}')"
  ran_ok "E8 a deleted raw key written encrypted" && pass "E8 a deleted key takes a record in the other mode"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K1" '{operation:"storage_delete",key:$k}')"
  ran_ok "E8 delete the re-written record" >/dev/null && [[ "$(out_field .deleted)" == true ]] || warn "E8 $K1 was not deleted — left in $PARENT's storage of $PROJECT"
  via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$K2" '{operation:"storage_delete",key:$k}')"
  ran_ok "E8 delete the encrypted record" >/dev/null && [[ "$(out_field .deleted)" == true ]] || warn "E8 $K2 was not deleted — left in $PARENT's storage of $PROJECT"
fi

# ── E9 sealed storage ────────────────────────────────────────────────────────

if want E9 && storage_gate; then
  log "E9 sealed records: encrypted, bound to their name, stored raw under its mac"
  NAME="sealed record $TAG"; VALUE="the sealed value of $TAG"; VALUE_HEX=$(hex_of "$VALUE")
  via_project "$PARENT" encryption-storage '{"operation":"all_encryption_keys"}'
  ran_ok "E9 storage build all_encryption_keys" && { remember_all_macs
    [[ -z "$MAC_ALPHA" || "$(out_field .keys.alpha.mac)" == "$MAC_ALPHA" ]] && pass "E9 the storage build holds the encryption build's alpha (one declaration, one project)" \
      || fail "E9 the storage build's alpha is another key than the encryption build's"; }
  SK=""
  via_project "$PARENT" encryption-storage "$(jq -nc --arg n "$NAME" --arg v "$VALUE" '{operation:"sealed_put",path:"alpha",key:$n,value:$v}')"
  if ran_ok "E9 sealed_put"; then
    SK=$(out_field .storage_key)
    [[ "$SK" =~ ^[0-9a-f]{64}$ ]] && pass "E9 sealed_put — stored under $SK" || fail "E9 the storage key is not a 32-byte hex: $SK"
    [[ "$(out_field .stored_len)" == $(( ${#VALUE_HEX} / 2 + 41 )) ]] && pass "E9 the stored bytes are the value's + 41" \
      || fail "E9 stored $(out_field .stored_len) bytes for a $(( ${#VALUE_HEX} / 2 ))-byte value"
  fi
  via_project "$PARENT" encryption-storage "$(jq -nc --arg d "$(hex_of "$NAME")" '{operation:"mac",path:"alpha",plaintext_hex:$d}')"
  ran_ok "E9 mac of the name" && { remember_mac "$(hex_of "$NAME")" "$(out_field .mac)"
    [[ -n "$SK" && "$(out_field .mac)" == "$SK" ]] && pass "E9 the storage key is mac(alpha, name)" || fail "E9 mac(alpha, name) is $(out_field .mac), the storage key $SK"; }
  via_project "$PARENT" encryption-storage "$(jq -nc --arg n "$NAME" '{operation:"sealed_get",path:"alpha",key:$n}')"
  ran_ok "E9 sealed_get" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/$VALUE_HEX" ]] \
    && pass "E9 sealed_get in a later run: the value" || fail "E9 sealed_get answered found=$(out_field .found) $(out_field .value)"; }
  STORED=""
  if [[ -n "$SK" ]]; then
    via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$SK" '{operation:"raw_get",key:$k}')"
    if ran_ok "E9 raw_get of the storage key"; then
      STORED=$(out_field .value_hex)
      [[ "${STORED:0:2}" == 01 ]] && pass "E9 the stored bytes start with the 0x01 format marker" || fail "E9 the stored bytes start with ${STORED:0:2}"
      (( ${#STORED} == ${#VALUE_HEX} + 82 )) && pass "E9 and are $(( ${#STORED} / 2 )) bytes: 0x01 ‖ nonce ‖ ciphertext ‖ tag" || fail "E9 $(( ${#STORED} / 2 )) bytes stored"
      [[ "$STORED" != *"$VALUE_HEX"* && "$STORED" != *"$(hex_of "$NAME")"* ]] && pass "E9 neither the value nor the name is in the stored bytes" \
        || fail "E9 the plaintext is IN the stored bytes"
    fi
    via_project "$PARENT" encryption-storage "$(jq -nc --arg p "$SK" '{operation:"storage_list",prefix:$p}')"
    ran_ok "E9 list the storage key" && { [[ "$(out_field '.keys | join(",")')" == "$SK" ]] && pass "E9 list-keys shows the mac name" || fail "E9 list-keys under $SK: $(out_field .keys)"; }
    via_project "$PARENT" encryption-storage "$(jq -nc --arg p "$NAME" '{operation:"storage_list",prefix:$p}')"
    ran_ok "E9 list the name" && { [[ "$(out_field '.keys | length')" == 0 ]] && pass "E9 no stored key is named after the record" || fail "E9 a stored key carries the name: $(out_field .keys)"; }
  fi
  if [[ -n "$STORED" ]]; then
    via_project "$PARENT" encryption-storage "$(jq -nc --arg c "$STORED" --arg a "$(hex_of "another record")" '{operation:"decrypt",path:"alpha",ciphertext_hex:$c,aad_hex:$a}')"
    answered_err "E9 the stored ciphertext moved under another name does not open" "decryption failed"
  fi
  via_project "$CALLER2" encryption-storage "$(jq -nc --arg n "$NAME" '{operation:"sealed_get",path:"alpha",key:$n}')"
  ran_ok "E9 $CALLER2 sealed_get" && { [[ "$(out_field .found)" == false ]] && pass "E9 $CALLER2 finds nothing under the name" || fail "E9 $CALLER2 found $(out_field .value)"; }
  if [[ -n "$SK" ]]; then
    via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$SK" '{operation:"storage_delete",key:$k}')"
    ran_ok "E9 cleanup" >/dev/null && [[ "$(out_field .deleted)" == true ]] || warn "E9 $SK was not deleted — left in $PARENT's storage of $PROJECT"
  fi
fi

# ── SC the storage cell ─────────────────────────────────────────────────────

# The account a record's row sits under in storage_data, when PSQL_CMD reads
# the coordinator's database: `cell_of <key>` prints it, or nothing.
PROJECT_UUID=""
cell_of() { # cell_of <key>
  sql_alive || return 0
  [[ -n "$PROJECT_UUID" ]] || PROJECT_UUID=$(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.uuid // empty' 2>/dev/null)
  [[ -n "$PROJECT_UUID" ]] || return 0
  sql_row "SELECT string_agg(account_id, ',') FROM storage_data WHERE project_uuid = '$PROJECT_UUID' AND key_hash = '$(printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1)' HAVING count(*) > 0" 3
}
# The row check, when the database is readable; otherwise a note.
row_under() { # row_under <row> <key> <account>
  local got
  got=$(cell_of "$2")
  if [[ -z "$got" ]]; then
    note "$1 — storage_data not read (PSQL_CMD unset, unreadable, or no row for the project's uuid)"
  elif [[ "$got" == "$3" ]]; then
    pass "$1 — storage_data: the row is under $3"
  else
    fail "$1 — storage_data: the row is under $got, not $3"
  fi
}

if want SC && storage_gate; then
  log "SC the storage cell: storage_account \"predecessor\" against the default"
  KD="$TAG/cell-direct"; KP="$TAG/cell-pred"; KS="$TAG/cell-signer"

  via_project "$PARENT" encryption-storage-pred "$(jq -nc --arg k "$KD" '{operation:"raw_set",key:$k,value_hex:"d1"}')"
  if ran_ok "SC3 direct raw_set (predecessor cell)"; then
    via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$KD" '{operation:"raw_get",key:$k}')"
    ran_ok "SC3 direct raw_get (signer cell)" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/d1" ]] \
      && pass "SC3 on a direct call the predecessor's cell is the signer's: one cell" \
      || fail "SC3 the storage build does not see what the predecessor build wrote on a direct call: found=$(out_field .found) $(out_field .value_hex)"; }
    row_under "SC3" "$KD" "$PARENT"
    via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$KD" '{operation:"storage_delete",key:$k}')"
    ran_ok "SC3 cleanup" >/dev/null && [[ "$(out_field .deleted)" == true ]] || warn "SC3 $KD was not deleted — left in $PARENT's storage of $PROJECT"
  fi

  if [[ "$RELAY_READY" != true ]]; then
    skip "SC1, SC2 relayed through a contract — $RELAY_WHY"
  else
    via_relay "$PARENT" encryption-storage-pred "$(jq -nc --arg k "$KP" '{operation:"raw_set",key:$k,value_hex:"b1"}')"
    if ran_ok "SC1 relayed raw_set"; then
      via_relay "$PARENT" encryption-storage-pred "$(jq -nc --arg k "$KP" '{operation:"raw_get",key:$k}')"
      ran_ok "SC1 relayed raw_get" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/b1" ]] \
        && pass "SC1 relayed again, the record is found" || fail "SC1 relayed again: found=$(out_field .found) $(out_field .value_hex)"; }
      via_relay "$CALLER2" encryption-storage-pred "$(jq -nc --arg k "$KP" '{operation:"raw_get",key:$k}')"
      ran_ok "SC1 $CALLER2 relayed raw_get" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/b1" ]] \
        && pass "SC1 $CALLER2 through the same relay finds it: the cell is the relay contract's, whoever signs" \
        || fail "SC1 $CALLER2 through the relay: found=$(out_field .found) — the cell is not the relay's"; }
      via_project "$PARENT" encryption-storage-pred "$(jq -nc --arg k "$KP" '{operation:"raw_get",key:$k}')"
      ran_ok "SC1 direct raw_get" && { [[ "$(out_field .found)" == false ]] \
        && pass "SC1 $PARENT's direct call does not find it: it is not in the signer's cell" \
        || fail "SC1 $PARENT's direct call found the relayed record — it landed in the signer's cell"; }
      row_under "SC1" "$KP" "$RELAY_CONTRACT"
      via_relay "$PARENT" encryption-storage-pred "$(jq -nc --arg k "$KP" '{operation:"storage_delete",key:$k}')"
      ran_ok "SC1 cleanup" >/dev/null && [[ "$(out_field .deleted)" == true ]] || warn "SC1 $KP was not deleted — left in $RELAY_CONTRACT's storage of $PROJECT"
    fi

    via_relay "$PARENT" encryption-storage "$(jq -nc --arg k "$KS" '{operation:"raw_set",key:$k,value_hex:"b2"}')"
    if ran_ok "SC2 relayed raw_set (no storage_account)"; then
      via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$KS" '{operation:"raw_get",key:$k}')"
      ran_ok "SC2 direct raw_get" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/b2" ]] \
        && pass "SC2 without the field a relayed record lands in the signer's cell: $PARENT's direct call finds it" \
        || fail "SC2 $PARENT's direct call does not find the relayed record: found=$(out_field .found)"; }
      via_relay "$CALLER2" encryption-storage "$(jq -nc --arg k "$KS" '{operation:"raw_get",key:$k}')"
      ran_ok "SC2 $CALLER2 relayed raw_get" && { [[ "$(out_field .found)" == false ]] \
        && pass "SC2 $CALLER2 through the same relay does not find it" \
        || fail "SC2 $CALLER2 through the relay found $PARENT's record — the cell is the relay's"; }
      row_under "SC2" "$KS" "$PARENT"
      via_project "$PARENT" encryption-storage "$(jq -nc --arg k "$KS" '{operation:"storage_delete",key:$k}')"
      ran_ok "SC2 cleanup" >/dev/null && [[ "$(out_field .deleted)" == true ]] || warn "SC2 $KS was not deleted — left in $PARENT's storage of $PROJECT"
    fi
  fi
fi

# ── E10 a type on an encryption key ─────────────────────────────────────────

if want E10; then
  log "E10 an encryption key that names a type is refused before the run starts"
  direct "$PARENT" encryption-typed '{"operation":"all_encryption_keys"}'
  refused_without_keys "E10 the typed build" 'unknown field `type`'
fi

# ── E7 no key material anywhere ─────────────────────────────────────────────

if want E7; then
  log "E7 no encryption key or mac subkey in any answer of the run"
  via_project "$PARENT" encryption '{"operation":"what_i_can_see"}'
  if ran_ok "E7 what_i_can_see"; then
    names=$(jq -r '.env | keys[]' <<<"$RUN_OUT" 2>/dev/null | grep -iE 'encrypt|secret|key' | tr '\n' ' ')
    [[ -z "$names" ]] && pass "E7 what_i_can_see — no environment variable is named for a key" \
      || finding "E7 what_i_can_see — environment variables named like keys: $names (the scan below checks their values)"
    [[ "$(jq -r '[.exercised[] | select(has("encryption_path")) | (.encrypt and .decrypt and .mac)] | all' <<<"$RUN_OUT" 2>/dev/null)" == true ]] \
      && pass "E7 every declared encryption key was used in that run before it looked" || fail "E7 what_i_can_see did not exercise every key"
  fi
  # Macs of known data, for the scan: alpha and beta of the gate.
  if [[ ! -s "$SEEN_MACS" ]]; then
    via_project "$PARENT" encryption '{"operation":"all_encryption_keys"}'
    ran_ok "E7 all_encryption_keys" && remember_all_macs
  fi
  sort -u "$SEEN_MACS" -o "$SEEN_MACS"
  if [[ ! -s "$SEEN_MACS" ]]; then
    fail "E7 the run saw no mac to test candidates against"
  else
    res=$(scan_for_keys "$ANSWERS" "$SEEN_MACS")
    tried=$(cut -d' ' -f1 <<<"$res"); hits=$(cut -d' ' -f2 <<<"$res")
    [[ "$hits" == 0 ]] \
      && pass "E7 $tried 32-byte values in the answers tried as AEAD key and as mac subkey; none reproduces any of the $(wc -l < "$SEEN_MACS" | tr -d ' ') macs seen" \
      || fail "E7 key material in the answers — $(cut -d' ' -f2- <<<"$res")"
  fi
fi

verdict "encryption keys"
