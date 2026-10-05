#!/usr/bin/env bash
# A public webhook receiver for the live suites, on this machine:
# `lib/hook_receiver.mjs` behind a Cloudflare quick tunnel (an anonymous
# https://*.trycloudflare.com address, no account).
#
#   tests/hook_receiver.sh start    # starts both, writes the env file
#   tests/hook_receiver.sh status   # running or not, and whether the public
#                                   # address answers
#   tests/hook_receiver.sh stop     # stops both, removes the env file
#
# `start` writes $STATE/hook.env (mode 0600):
#   HOOK_URL                the receiver: answers 200, keeps what it is sent
#   HOOK_LOG_URL            its log, read with GET ({"requests": [...]})
#   HOOK_REDIRECT_URL       a receiver that answers 307 to HOOK_URL (W3)
#   HOOK_REDIRECT_LOG_URL   its log
# Every URL carries a random token in its path: whoever holds it can send to
# the receiver and read its log, so the file is not printed and the URLs are
# not put on a command line. A suite reads them where it runs:
#
#   set -a; source ~/.local/state/outlayer-hook/hook.env; set +a
#   ONLY=W1,W3,NT7 .idea/testnet-runners/run_tasks_alice.sh
#
# The tunnel's address changes on every start; the env file follows it. The
# log lives in the receiver's memory only, and goes with `stop`.
#
# Requires: node, cloudflared (brew install cloudflared), curl, openssl.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="${HOOK_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/outlayer-hook}"
ENV_FILE="$STATE/hook.env"

alive() { [[ -f "$STATE/$1.pid" ]] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }

stop() {
  for p in tunnel receiver; do
    if alive "$p"; then kill "$(cat "$STATE/$p.pid")" 2>/dev/null; fi
    rm -f "$STATE/$p.pid"
  done
  rm -f "$ENV_FILE"
  echo "hook receiver stopped"
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
    echo "hook receiver already running; env: $ENV_FILE"
    return 0
  fi
  stop >/dev/null
  mkdir -p "$STATE" && chmod 700 "$STATE"

  local token port url i
  token=$(openssl rand -hex 24)
  # A free port, chosen by the OS.
  port=$(node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')

  HOOK_TOKEN="$token" HOOK_PORT="$port" nohup node "$SCRIPT_DIR/lib/hook_receiver.mjs" \
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
  for i in $(seq 1 30); do
    [[ "$(public_ok)" == 200 ]] && { echo "hook receiver up at a public trycloudflare.com address; env: $ENV_FILE"; return 0; }
    sleep 2
  done
  echo "the receiver runs, but its public address did not answer in 60 s (see $STATE/tunnel.log)" >&2
  exit 1
}

status() {
  local r t
  r=$(alive receiver && echo running || echo stopped)
  t=$(alive tunnel && echo running || echo stopped)
  echo "receiver: $r, tunnel: $t, env file: $([[ -f "$ENV_FILE" ]] && echo present || echo absent)"
  [[ -f "$ENV_FILE" ]] && echo "public address answers: $(public_ok)"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) echo "usage: $0 start|status|stop" >&2; exit 2 ;;
esac
