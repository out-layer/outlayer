#!/usr/bin/env bash
# The RPC every live suite reads the chain through: a FastNEAR endpoint WITH an
# API key. The unkeyed host is rate-limited and slow, and its timeouts read
# exactly like product failures. Source this after NETWORK is set (default
# testnet); an RPC_URL already in the environment wins untouched.
#
# The key comes from FASTNEAR_API_KEY, else from near-cli's own config (the
# `rpc_url` of the matching network, wherever near-cli keeps its config on this
# OS), and never from this file. Without a key the suite runs on the unkeyed
# host and says so on stderr — read that line before believing a timeout.
NETWORK="${NETWORK:-testnet}"
fastnear_key() {
  [[ -n "${FASTNEAR_API_KEY:-}" ]] && { printf '%s' "$FASTNEAR_API_KEY"; return 0; }
  local cfg key
  for cfg in "${NEAR_CLI_CONFIG:-}" \
             "$HOME/Library/Application Support/near-cli/config.toml" \
             "${XDG_CONFIG_HOME:-$HOME/.config}/near-cli/config.toml"; do
    [[ -n "$cfg" && -r "$cfg" ]] || continue
    key=$(grep -oE "rpc\.${NETWORK}\.fastnear\.com/?\?apiKey=[^\"'&[:space:]]+" "$cfg" 2>/dev/null | head -1 | sed 's/.*apiKey=//')
    [[ -n "$key" ]] && { printf '%s' "$key"; return 0; }
  done
  return 1
}
if [[ -z "${RPC_URL:-}" ]]; then
  _k="$(fastnear_key || true)"
  if [[ -n "$_k" ]]; then
    RPC_URL="https://rpc.${NETWORK}.fastnear.com/?apiKey=$_k"
  else
    RPC_URL="https://rpc.${NETWORK}.fastnear.com"
    echo "⚠ no FastNEAR API key (FASTNEAR_API_KEY or near-cli config): using the unkeyed RPC, expect rate limits and timeouts" >&2
  fi
  unset _k
fi
