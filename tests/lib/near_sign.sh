# shellcheck shell=bash
# `near … sign-with-keychain` reads the signer's whole access-key list before it
# signs, and the RPC refuses that list for an account with many keys
# (TOO_MANY_ACCESS_KEYS) — the call then fails before any transaction exists.
# `sign-with-legacy-keychain` reads only the one key it holds. This wrapper
# keeps every suite's `near` calls as written and swaps the method whenever the
# signer has a key file in the legacy keychain; an account whose key lives only
# in the OS keychain (e.g. one created with `save-to-keychain`) signs as before.
near() {
  local args=("$@") i signer="" net="${NETWORK:-testnet}"
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[i]}" in
      sign-as) signer="${args[i + 1]:-}"; break ;;
    esac
  done
  if [[ -z "$signer" ]]; then
    for ((i = 0; i < ${#args[@]}; i++)); do
      case "${args[i]}" in
        construct-transaction|deploy|delete-account|add-key|delete-keys|tokens) signer="${args[i + 1]:-}"; break ;;
      esac
    done
  fi
  for ((i = 0; i < ${#args[@]}; i++)); do
    [[ "${args[i]}" == network-config ]] && net="${args[i + 1]:-$net}"
  done
  if [[ -n "$signer" && -f "$HOME/.near-credentials/$net/$signer.json" ]]; then
    for ((i = 0; i < ${#args[@]}; i++)); do
      [[ "${args[i]}" == sign-with-keychain ]] && args[i]=sign-with-legacy-keychain
    done
  fi
  command near "${args[@]}"
}

# A suite that writes `curl … "$RPC_URL" …` would put the keyed URL on curl's
# command line, which `ps` shows to every process on the box. This wrapper
# takes that argument out and hands the URL to curl as a config line on a
# file descriptor instead; every other curl call passes through untouched.
curl() {
  local args=() a url=""
  for a in "$@"; do
    if [[ -n "${RPC_URL:-}" && "$a" == "$RPC_URL" && "$a" == *apiKey=* ]]; then url=$a; else args+=("$a"); fi
  done
  if [[ -n "$url" ]]; then
    command curl -K <(printf 'url = "%s"\n' "$url") "${args[@]}"
  else
    command curl "$@"
  fi
}

# The reason a near-cli or outlayer-cli call failed, safe to print. Their raw
# output can hold the RPC URL — a transport error echoes the endpoint, key and
# all — so a suite never prints it, not even its tail. This picks the contract's
# panic, else the error class, else the CLI's own `Error:` line; anything picked
# that is URL-shaped is withheld whole rather than filtered. Byte-wise (`LC_ALL=C
# grep -a`): a panic with non-ASCII text makes BSD grep call the output binary.
#   near_why "$OUT"          near_why < file
near_why() {
  local out m
  if (( $# )); then out=$1; else out=$(cat); fi
  m=$(LC_ALL=C grep -aoE 'Smart contract panicked: [^"]{1,250}' <<<"$out" | head -1)
  [[ -z "$m" ]] && m=$(LC_ALL=C grep -aoE '(does not have enough balance|InvalidTxError|ActionError|InvalidNonce|NotEnoughBalance|LackBalanceForState|AccessKeyNotFound|AccountDoesNotExist|TOO_MANY_ACCESS_KEYS|Tx not found|TIMEOUT_ERROR|timed out)[^"]{0,160}' <<<"$out" | head -1)
  [[ -z "$m" ]] && m=$(LC_ALL=C grep -aE '^(Error|error):' <<<"$out" | head -1 | head -c 300)
  # near-cli-rs prints a bare `Error:` and the reason on the report lines below
  # it (`   0: …`, `   1: …`); take those too, or the answer is the empty word.
  if [[ "$m" =~ ^(Error|error):[[:space:]]*$ ]]; then
    m="$m $(LC_ALL=C grep -aE '^[[:space:]]+[0-9]+: ' <<<"$out" | head -3 | sed -E 's/^[[:space:]]+//' | head -c 300)"
  fi
  if [[ -z "$m" ]]; then
    echo "no contract or CLI error in the output (withheld: it can carry the RPC URL)"
  elif LC_ALL=C grep -aqiE 'https?:|apikey|rpc\.|fastnear' <<<"$m"; then
    echo "a transport error (withheld: it names the RPC endpoint)"
  else
    LC_ALL=C tr '\n' ' ' <<<"$m"
  fi
}
