#!/usr/bin/env bash
# A public webhook receiver for the live suites, on this machine:
# `lib/hook_receiver.mjs` behind a Cloudflare quick tunnel (an anonymous
# https://*.trycloudflare.com address, no account).
#
#   tests/hook_receiver.sh start    # starts both, writes the env file
#   tests/hook_receiver.sh ensure   # leaves one that answers at its public
#                                   # address: the running one, or a new one
#   tests/hook_receiver.sh status   # running or not, and whether the public
#                                   # address answers
#   tests/hook_receiver.sh stop     # stops both, removes the env file
#   tests/hook_receiver.sh env-file # prints where the env file is
#
# The receiver verifies every request it is sent under the webhook keys of
# one API (`GET <base>/wallet/v1/webhook-keys`): the one COORDINATOR_URL
# names, the testnet API when it is unset — the default of the suites. A
# webhook whose signature does not hold is answered 401 and kept in the log
# with the reason.
#
# One receiver per API: each has its own state directory, named after the
# API's host, under ${HOOK_STATE_DIR:-~/.local/state/outlayer-hook}. Every
# command acts on the receiver of the API COORDINATOR_URL names and on no
# other, so a suite on testnet and one on mainnet each keep their own.
#
# `start` writes $STATE/hook.env (mode 0600):
#   HOOK_API_BASE           the API whose webhooks the receiver verifies
#   HOOK_URL                the receiver: answers 200 to a webhook whose
#                           signature holds, keeps what it is sent
#   HOOK_LOG_URL            its log, read with GET ({"requests": [...]})
#   HOOK_REDIRECT_URL       a receiver that answers 307 to HOOK_URL (W3)
#   HOOK_REDIRECT_LOG_URL   its log
# Every URL carries a random token in its path: whoever holds it can send to
# the receiver and read its log, so the file is not printed and the URLs are
# not put on a command line. `tests/tasks_e2e.sh` starts one itself with
# `ensure` when a row needs it and stops it on exit; another suite reads them
# where it runs:
#
#   tests/hook_receiver.sh ensure
#   set -a; source "$(tests/hook_receiver.sh env-file)"; set +a
#
# The tunnel's address changes on every start; the env file follows it. The
# log lives in the receiver's memory only, and goes with `stop`.
#
# A quick tunnel is Cloudflare's to drop: once its connection is lost — the
# machine slept, the network moved — the name is gone and cloudflared cannot
# take it back ("Tunnel not found"). `ensure` sees that the public address no
# longer answers and starts a new one, at a new address.
#
# Requires: node, cloudflared (brew install cloudflared), curl, openssl.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_BASE="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
API_BASE="${API_BASE%/}"
# The state of this API's receiver: a directory named after the API's host
# (and port), with every other character made `_`.
API_NAME=$(printf '%s' "${API_BASE#*://}" | tr -c 'A-Za-z0-9.-' '_')
[[ -n "$API_NAME" && "$API_NAME" != . && "$API_NAME" != .. ]] || { echo "COORDINATOR_URL names no host" >&2; exit 2; }
STATE="${HOOK_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/outlayer-hook}/$API_NAME"
ENV_FILE="$STATE/hook.env"

alive() { [[ -f "$STATE/$1.pid" ]] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }

stop() {
  for p in tunnel receiver; do
    if alive "$p"; then kill "$(cat "$STATE/$p.pid")" 2>/dev/null; fi
    rm -f "$STATE/$p.pid"
  done
  rm -f "$ENV_FILE"
  echo "hook receiver of $API_BASE stopped"
}

# The tunnel's host, from the env file.
public_host() {
  ( set -a; source "$ENV_FILE"; set +a; h=${HOOK_URL#https://}; printf '%s' "${h%%/*}" )
}

# `health` through the public address: 200 "ok" once the tunnel routes.
public_ok() {
  ( set -a; source "$ENV_FILE"; set +a
    curl -s --max-time 10 -o /dev/null -w '%{http_code}' "${HOOK_URL%/hook}/health" ) 2>/dev/null
}

# A fresh quick-tunnel name is published a few seconds after the tunnel
# answers. Asking this machine's resolver before then makes it remember "no
# such name" for minutes, so the name is first awaited with `dig`, which asks
# a DNS server directly and leaves the resolver's cache alone.
await_dns() {
  local host i
  host=$(public_host)
  for i in $(seq 1 60); do
    [[ -n "$(dig +short "$host" @1.1.1.1 2>/dev/null | head -1)" ]] && return 0
    sleep 2
  done
  return 1
}

start() {
  command -v cloudflared >/dev/null || { echo "cloudflared is not installed: brew install cloudflared" >&2; exit 1; }
  command -v node >/dev/null || { echo "node is not installed" >&2; exit 1; }
  if alive receiver && alive tunnel && [[ -f "$ENV_FILE" ]]; then
    echo "hook receiver of $API_BASE already running; env: $ENV_FILE"
    return 0
  fi
  stop >/dev/null
  mkdir -p "$STATE" && chmod 700 "$STATE" "$(dirname "$STATE")"

  local token port url i
  token=$(openssl rand -hex 24)
  # A free port, chosen by the OS.
  port=$(node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')

  HOOK_TOKEN="$token" HOOK_PORT="$port" HOOK_API_BASE="$API_BASE" nohup node "$SCRIPT_DIR/lib/hook_receiver.mjs" \
    > "$STATE/receiver.log" 2>&1 &
  echo $! > "$STATE/receiver.pid"

  nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$port" > "$STATE/tunnel.log" 2>&1 &
  echo $! > "$STATE/tunnel.pid"

  url=""
  for i in $(seq 1 30); do
    url=$(grep -aoE 'https://[a-z0-9-]+\.trycloudflare\.com' "$STATE/tunnel.log" | head -1)
    [[ -n "$url" ]] && break
    sleep 1
  done
  if [[ -z "$url" ]]; then
    echo "the tunnel gave no address in 30 s (see $STATE/tunnel.log)" >&2
    stop >/dev/null
    exit 1
  fi

  ( umask 077
    cat > "$ENV_FILE" <<EOF
HOOK_API_BASE=$API_BASE
HOOK_URL=$url/$token/hook
HOOK_LOG_URL=$url/$token/hook/log
HOOK_REDIRECT_URL=$url/$token/redirect
HOOK_REDIRECT_LOG_URL=$url/$token/redirect/log
EOF
  )

  if ! await_dns; then
    echo "the tunnel's name was not published in 120 s (see $STATE/tunnel.log)" >&2
    exit 1
  fi
  for i in $(seq 1 60); do
    [[ "$(public_ok)" == 200 ]] && { echo "hook receiver up at a public trycloudflare.com address, verifying the webhooks of $API_BASE; env: $ENV_FILE"; return 0; }
    sleep 2
  done
  echo "the receiver runs, but its public address did not answer in 120 s (see $STATE/tunnel.log)" >&2
  exit 1
}

# A receiver that answers at its public address: the running one, or a new
# one in its place — at a new address, so whoever named the old one names
# the new one.
ensure() {
  if alive receiver && alive tunnel && [[ -f "$ENV_FILE" && "$(public_ok)" == 200 ]]; then
    echo "hook receiver up, verifying the webhooks of $API_BASE; env: $ENV_FILE"
    return 0
  fi
  stop >/dev/null
  start
}

status() {
  local r t
  r=$(alive receiver && echo running || echo stopped)
  t=$(alive tunnel && echo running || echo stopped)
  echo "receiver: $r, tunnel: $t, env file: $([[ -f "$ENV_FILE" ]] && echo present || echo absent)"
  if [[ -f "$ENV_FILE" ]]; then
    echo "public address answers: $(public_ok)"
  fi
  echo "verifies the webhooks of: $API_BASE (state: $STATE)"
}

case "${1:-}" in
  start) start ;;
  ensure) ensure ;;
  stop) stop ;;
  status) status ;;
  env-file) printf '%s\n' "$ENV_FILE" ;;
  *) echo "usage: $0 start|ensure|status|stop|env-file" >&2; exit 2 ;;
esac
