#!/usr/bin/env bash
# Shared by the secrets suites — `wasi-examples/test-secrets-example/tests/03_project_model.sh`
# and `tests/secrets_security_e2e.sh`: fixture accounts, the stored row as the
# chain reports it, `store` / `set_access` / `delete_row` that wait for finality,
# and one run on chain or over HTTPS judged the same way.
#
# Source AFTER hos_common.sh and after these are set:
#   PARENT        the row owner and on-chain signer (key in the keychain; the
#                 outlayer CLI's credentials must be this account)
#   PROJECT       the project every `run_as` executes
#   DEPOSIT       what `run_as` attaches (e.g. '0.1 NEAR')
# and, from hos_common.sh: CONTRACT_ID NETWORK RPC_URL COORDINATOR_URL.
#
# Every run sets RUN_OK (true / false / absent), RUN_ERR (the reason) and
# RUN_OUT (the module's own JSON answer).

# ── fixture helpers ──────────────────────────────────────────────────────────

account_is_on_chain() {
  local out
  out=$(curl -sS "$RPC_URL" -H 'content-type: application/json' -d "$(jq -nc --arg a "$1" \
        '{jsonrpc:"2.0",id:1,method:"query",
          params:{request_type:"view_account",finality:"final",account_id:$a}}')" 2>/dev/null)
  [[ -n "$(jq -r '.result.amount // empty' <<<"$out")" ]]
}

make_account() { # make_account <name> <parent> <amount>
  if account_is_on_chain "$1"; then note "$1 is already there"; return 0; fi
  local signer=with-keychain
  [[ "$2" != "$PARENT" ]] && signer=with-legacy-keychain
  near --quiet account create-account fund-myself "$1" "$3" \
    autogenerate-new-keypair save-to-legacy-keychain \
    sign-as "$2" network-config "$NETWORK" "sign-$signer" send >/dev/null 2>&1
  account_is_on_chain "$1" || { echo "✗ could not create $1" >&2; exit 1; }
  note "created $1 with $3"
}

accessor_json() { jq -nc --arg p "$1" '{Project:{project_id:$p}}'; }

# The stored row, as the chain reports it (ciphertext + condition), or empty.
#
# A row is keyed by OWNER as much as by accessor and profile, and the owner is
# not always the account a suite signs as: a custody wallet owns its rows as its
# own implicit account. `row_of` reads the common case, `row_of_owner` any.
row_of_owner() { # row_of_owner <project> <profile> <owner>
  near_view "$CONTRACT_ID" get_secrets "$(jq -nc --argjson a "$(accessor_json "$1")" --arg pr "$2" --arg o "$3" \
    '{accessor:$a, profile:$pr, owner:$o}')"
}

row_of() { # row_of <project> <profile>
  row_of_owner "$1" "$2" "$PARENT"
}

# Wait until the row's `updated_at` moves past a value: `outlayer secrets set`
# and `near call` return once EXECUTED, `near_view` reads FINAL.
wait_row_after() { # wait_row_after <project> <profile> <previous updated_at> [owner]
  local after=$3 owner=${4:-$PARENT} i
  for i in $(seq 1 15); do
    after=$(jq -r '.updated_at // 0' <<<"$(row_of_owner "$1" "$2" "$owner")")
    [[ "$after" != "$3" ]] && return 0
    sleep 2
  done
  return 1
}

# The outlayer CLI: OUTLAYER_BIN when a suite names one, else a binary built
# from the checkout next door, else whatever is on PATH.
#
# The guard is not politeness. A binary that predates the priced access edit
# writes a whitelist as a bare array, which the contract refuses to deserialize,
# so every row that stores through the CLI dies for a reason that has nothing to
# do with what it tests — and the refusal rows among them would PASS on it.
OUTLAYER_CLI_DIR="${OUTLAYER_CLI_DIR:-$HOME/projects/outlayer-cli}"
# A bare "outlayer" is the default, not a choice: prefer the local build over
# whatever release binary happens to sit on PATH. Only an explicit path wins.
if [[ ( -z "${OUTLAYER_BIN:-}" || "${OUTLAYER_BIN:-}" == "outlayer" ) && -x "$OUTLAYER_CLI_DIR/target/release/outlayer" ]]; then
  OUTLAYER_BIN="$OUTLAYER_CLI_DIR/target/release/outlayer"
fi
OUTLAYER_BIN="${OUTLAYER_BIN:-outlayer}"
OUTLAYER_BIN_PATH="$(command -v "$OUTLAYER_BIN" 2>/dev/null || echo "$OUTLAYER_BIN")"
# The CLI reaches the chain itself, and its built-in endpoint is the FREE one.
# That host is rate-limited, and a request it drops surfaces as
# "error while sending payload" from inside `secrets set` — indistinguishable
# from the product refusing. Hand the CLI the keyed endpoint this suite already
# built (`lib/rpc.sh`), and never read the variable back: it carries the key.
[[ -n "${RPC_URL:-}" ]] && export OUTLAYER_RPC_URL="${OUTLAYER_RPC_URL:-$RPC_URL}"
# Counted, not `grep -q`: under `pipefail` a quiet grep exits at the first
# match, `strings` dies of SIGPIPE, and the pipeline's 141 reads as "the symbol
# is missing" — condemning the very binary that carries it.
if [[ -x "$OUTLAYER_BIN_PATH" ]] && [[ "$(strings "$OUTLAYER_BIN_PATH" 2>/dev/null | grep -c estimate_storage_cost)" == "0" ]]; then
  echo "✗ $OUTLAYER_BIN_PATH predates the priced access edit: it writes a whitelist shape the contract refuses." >&2
  echo "  Build it:  cargo build --release --manifest-path $OUTLAYER_CLI_DIR/Cargo.toml   (or set OUTLAYER_BIN)" >&2
  exit 1
fi

store() { # store <project> <profile> <secrets-json> <access>   (the CLI signs as PARENT)
  local before out
  before=$(jq -r '.updated_at // 0' <<<"$(row_of "$1" "$2")")
  out=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set "$3" --project "$1" --profile "$2" --access "$4" 2>&1) \
    || { echo "✗ could not store $1/$2: $(tail -1 <<<"$out" | head -c 200)" >&2; exit 1; }
  wait_row_after "$1" "$2" "$before" || { echo "✗ $1/$2 never became final" >&2; exit 1; }
  note "stored $1/$2 ($4)"
}

# What this condition costs to store, in yoctoNEAR, priced by the contract
# itself against the row's real ciphertext. A condition is stored bytes, so an
# edit that grows one has to fund the growth; attaching the whole estimate is
# always enough, because the deposit already held is credited towards it and
# the excess comes back in the same transaction.
access_price() { # access_price <project> <profile> <access-json> [owner]
  local owner=${4:-$PARENT} row cipher
  row=$(row_of_owner "$1" "$2" "$owner")
  cipher=$(jq -r '.encrypted_secrets // ""' <<<"$row" 2>/dev/null)
  near_view "$CONTRACT_ID" estimate_storage_cost \
    "$(jq -nc --argjson a "$(accessor_json "$1")" --arg pr "$2" --arg o "$owner" \
        --arg c "$cipher" --argjson x "$3" \
      '{accessor:$a, profile:$pr, owner:$o, encrypted_secrets_base64:$c, access:$x, vault_id:null}')" \
    2>/dev/null | tr -d '"'
}

update_access_call() { # update_access_call <json-args> <deposit>
  near --quiet contract call-function as-transaction "$CONTRACT_ID" update_access \
    json-args "$1" prepaid-gas '30.0 Tgas' attached-deposit "$2" \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send
}

set_access() { # set_access <project> <profile> <access-json>
  local before price args out
  before=$(jq -r '.updated_at // 0' <<<"$(row_of "$1" "$2")")
  price=$(access_price "$1" "$2" "$3")
  # A condition the estimator cannot price is one the contract will refuse
  # anyway; 1 NEAR keeps the refusal about the condition rather than the money.
  [[ "$price" =~ ^[0-9]+$ ]] || price=1000000000000000000000000
  args=$(jq -nc --argjson a "$(accessor_json "$1")" --arg pr "$2" --argjson x "$3" \
    '{accessor:$a, profile:$pr, new_access:$x}')
  # What a failure here is worth reporting AS. A transaction refused for its
  # CONTENT is a verdict; one refused because two transactions from the same key
  # raced, or the RPC timed out, is not, and a suite that exits on the second
  # reports noise as product failure. So: one retry on a transient refusal, and
  # enough of the message to tell the two apart.
  local deposit_used="$price yoctoNEAR" transient=0
  while :; do
    out=$(update_access_call "$args" "$deposit_used" 2>&1) && break
    # Changing the deposit's SPELLING is not a retry. A contract that predates
    # the deposit refuses any deposit at all, and that answer is free: it must
    # not consume the retry budget the transient refusals need.
    if [[ "$deposit_used" != "0 NEAR" ]] && grep -qi "accept deposit\|not payable" <<<"$out"; then
      note "the deployed contract predates the update_access deposit: retrying without one"
      deposit_used='0 NEAR'
      continue
    fi
    # `Transaction has expired` means the block hash aged out before the RPC
    # took the transaction. It says nothing about the condition under test.
    if (( transient < 3 )) && grep -qiE "expired|nonce|timed out|timeout|Tx not found|connection|50[23]" <<<"$out"; then
      transient=$((transient + 1))
      note "update_access hit a transient refusal ($transient/3), retrying"
      sleep $((transient * 5))
      continue
    fi
    echo "✗ update_access failed for $1/$2 (deposit $deposit_used):" >&2
    grep -viE '^\s*$' <<<"$out" | tail -12 | head -c 900 >&2
    echo >&2
    exit 1
  done
  wait_row_after "$1" "$2" "$before" || { echo "✗ $1/$2 access change never became final" >&2; exit 1; }
  note "$1/$2 access → $(jq -c 'if type=="string" then . else keys[0] end' <<<"$3")"
}

# row_is_gone <project> <profile> — true only on an ANSWER that carries no row.
# An unreadable answer is not an answer: `row_of` yields the row, the literal
# ERR, or nothing, and `.encrypted_secrets // empty` maps the last two to the
# same empty string as a deleted row.
row_is_gone() {
  local r; r=$(row_of "$1" "$2")
  jq empty >/dev/null 2>&1 <<<"$r" || return 1
  [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$r")" ]]
}

delete_row() { # delete_row <project> <profile>
  # The near-cli output is KEPT: a delete that fails for a nonce raced by the
  # row above it and a delete the contract refused look identical once the
  # message is thrown away, and the caller is told to remove the row by hand
  # either way. One retry, because the first kind passes on its own — but the
  # chain is asked first, because `delete_secrets` PANICS on a row that is
  # already gone ("Secrets not found"), so retrying a delete that landed and
  # merely lost its answer would turn a success into a fatal suite abort.
  local out rc i
  for i in 1 2; do
    out=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" delete_secrets \
      json-args "$(jq -nc --argjson a "$(accessor_json "$1")" --arg pr "$2" '{accessor:$a, profile:$pr}')" \
      prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
      sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send 2>&1); rc=$?
    [[ $rc -eq 0 ]] && break
    row_is_gone "$1" "$2" && { note "deleted $1/$2 (the answer was lost; the row is gone)"; return 0; }
    [[ $i -eq 1 ]] && sleep 4
  done
  [[ $rc -eq 0 ]] || {
    echo "✗ delete_secrets failed for $1/$2: $(grep -oE 'panic_msg: [^,}]*|[Ee]rror: .*' <<<"$out" | head -2 | tr '\n' ' ' | head -c 200)" >&2
    exit 1; }
  for i in $(seq 1 15); do
    [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$(row_of "$1" "$2")")" ]] && { note "deleted $1/$2"; return 0; }
    sleep 2
  done
  echo "✗ $1/$2 still on chain after delete" >&2; exit 1
}

whitelist() { jq -nc '$ARGS.positional' --args "$@" | jq -c '{Whitelist:{accounts:.}}'; }

# ── one run, on chain ────────────────────────────────────────────────────────
#
# Sets RUN_OK / RUN_ERR from the completion event and RUN_OUT from the module's
# own answer. `run_as <signer> [owner/profile] [input-json]`; an empty second
# argument names no secret at all.
RUN_OK=""; RUN_ERR=""; RUN_OUT=""
# `run_as <signer> [owner/profile] [input-json] [version_key]`. A fourth
# argument pins a published version instead of the active one: pinning is a
# field of the `Project` SOURCE, not of the request, so the project and the
# stored rows stay the same and only the artefact changes — which is what it
# takes to show that a behaviour comes from the wasm's own manifest.
run_as() {
  local signer=$1 ref=${2:-} input=${3:-'{"message":"probe"}'} version=${4:-} out ev args signer_flag=with-legacy-keychain
  [[ "$signer" == "$PARENT" ]] && signer_flag=with-keychain
  args=$(jq -nc --arg p "$PROJECT" --arg i "$input" \
    '{source:{Project:{project_id:$p}}, input_data:$i,
      resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}}')
  if [[ -n "$version" ]]; then
    args=$(jq -c --arg v "$version" '.source.Project.version_key = $v' <<<"$args")
  fi
  if [[ -n "$ref" ]]; then
    args=$(jq -c --arg o "${ref%%/*}" --arg pr "${ref#*/}" '. + {secrets_ref:{profile:$pr, account_id:$o}}' <<<"$args")
  fi
  out=$(near contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$args" prepaid-gas '300.0 Tgas' attached-deposit "$DEPOSIT" \
    sign-as "$signer" network-config "$NETWORK" "sign-$signer_flag" send 2>&1)
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  if [[ -z "$ev" ]]; then
    # A send that expired on its block hash, or never left the CLI, produces no
    # event — and no verdict about the product. It is also transient, so it is
    # worth one retry before the row is written off.
    # A send that TIMED OUT may have landed, and so may one the RPC answered
    # `Tx not found` for (it has not seen the transaction YET), or one whose
    # connection dropped mid-answer: resending any of those would run the
    # request twice and let the second event overwrite the first verdict.
    # Only a send the RPC most likely never took — an expired block hash, no
    # connection at all — is retried.
    if grep -qiE "expired|connection refused|dns error|could not resolve|failed to connect" <<<"$out"; then
      note "the send never landed (transient), retrying once for $signer"
      sleep 5
      out=$(near contract call-function as-transaction "$CONTRACT_ID" request_execution \
        json-args "$args" prepaid-gas '300.0 Tgas' attached-deposit "$DEPOSIT" \
        sign-as "$signer" network-config "$NETWORK" "sign-$signer_flag" send 2>&1)
      ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
    fi
  fi
  # The CLI's whole transcript, for the rows that judge a refusal the CONTRACT
  # makes before yielding — there is no event then, only the panic's text.
  RUN_RAW="$out"
  if [[ -z "$ev" ]]; then
    RUN_OK=absent; RUN_ERR=""; RUN_OUT=""
    note "no completion event from $signer: $(grep -iE 'error|fail|panick|reset|limit' <<<"$out" | head -2 | head -c 300)"
    return 0
  fi
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev" 2>/dev/null)
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev" 2>/dev/null)
  RUN_OUT=$(awk '/Function execution return value/{getline; print}' <<<"$out" \
    | jq -c 'select(. != null) | if type=="string" then fromjson else . end' 2>/dev/null)
}

# ── one run, over HTTPS ──────────────────────────────────────────────────────
#
# `call_https <payment-key> <project> [owner/profile] [input-json] [extra curl args...]`
call_https() {
  local key=$1 project=$2 ref=${3:-} input=${4:-'{"message":"probe"}'}; shift 4 2>/dev/null || shift $#
  local body
  body=$(jq -nc --argjson i "$input" '{input:$i}')
  if [[ -n "$ref" ]]; then
    body=$(jq -c --arg o "${ref%%/*}" --arg pr "${ref#*/}" '. + {secrets_ref:{profile:$pr, account_id:$o}}' <<<"$body")
  fi
  https_post "$key" "$project" "$body" "$@"
}

# `https_post <payment-key> <project> <body> [extra curl args...]` — the body
# sent verbatim (it may be malformed on purpose). Also leaves HTTP_CODE (`000`
# when nothing answered within 90 s) and ANS (the raw body) for a caller that
# judges the door rather than the run.
HTTP_CODE=""; ANS=""
https_post() {
  local key=$1 project=$2 body=$3; shift 3
  RUN_RAW=""   # an on-chain transcript is `run_as`'s; none belongs to this call
  throttle
  local raw
  raw=$(curl -sS --max-time 90 -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/call/$project" \
    -H "X-Payment-Key: $key" -H 'Content-Type: application/json' "$@" --data-binary "$body" 2>&1)
  HTTP_CODE=${raw##*HTTP:}; ANS=${raw%$'\n'HTTP:*}
  # The envelope is `{call_id, status, output, …}` on a run and `{error, …}` on a
  # refusal — there is no `success` field. `status: completed` is the run that
  # ran; anything else, or a non-2xx, is a refusal whose reason is in the body.
  RUN_OUT=$(jq -c '.output | if type=="string" then fromjson else . end' <<<"$ANS" 2>/dev/null)
  RUN_ERR=$(jq -r '.error // .message // .status // ""' <<<"$ANS" 2>/dev/null)
  if [[ "$HTTP_CODE" == 2* ]] && [[ "$(jq -r '.status // ""' <<<"$ANS" 2>/dev/null)" == "completed" ]]; then
    RUN_OK=true
  elif jq -e . <<<"$ANS" >/dev/null 2>&1; then
    RUN_OK=false
  else
    RUN_OK=absent
    note "no JSON answer (HTTP $HTTP_CODE): $(head -c 200 <<<"$ANS")"
  fi
}

field() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$RUN_OUT" 2>/dev/null; }
secret_value() { jq -r --arg k "$1" '.secrets[]? | select(.key==$k) | .value // empty' <<<"$RUN_OUT" 2>/dev/null; }

