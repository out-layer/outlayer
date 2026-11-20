#!/usr/bin/env bash
# Run a worker as a systemd service instead of in a screen: the same binary and
# env file `run_worker.sh` uses, restarted on failure and on reboot, logs in
# journald.
#
# Build first (cd worker && cargo build --release), then, as root, from the
# repository root:
#
#   sudo ./scripts/worker_service.sh .env.mainnet.worker1         create (or refresh) + start
#   sudo ./scripts/worker_service.sh .env.mainnet.worker1 stop    stop + remove
#
# The service is named after the env file: `.env.mainnet.worker1` →
# `outlayer-worker-mainnet-worker1`. It runs as the owner of the checkout (never
# root), with `worker/` as its working directory.
#
# The env file is copied to /etc/outlayer-worker/<name>.env (root, 0600), read
# as the checkout's owner: the service never follows a path that owner could
# point at a file only root may read. After editing the env file, run this
# script again — it copies it anew and restarts the service. After a rebuild:
# `systemctl restart outlayer-worker-<name>`.
set -euo pipefail

die() { echo "✗ $*" >&2; exit 1; }

ENV_FILE="${1:?usage: sudo ./scripts/worker_service.sh <env file in worker/> [stop]}"
ACTION="${2:-start}"

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
# A file name in worker/, nothing more: it goes into the unit and into a path.
[[ "$ENV_FILE" =~ ^[A-Za-z0-9._-]+$ && "$ENV_FILE" != . && "$ENV_FILE" != .. ]] \
  || die "env file: a name in worker/ (letters, digits, . _ -), e.g. .env.mainnet.worker1"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# systemd splits ExecStart on spaces and expands % specifiers.
[[ "$REPO" =~ ^[A-Za-z0-9/._-]+$ ]] || die "checkout path '$REPO': letters, digits, / . _ - only"
WORKER_DIR="$REPO/worker"
SUFFIX="$(printf '%s' "$ENV_FILE" | sed -E 's/^\.env\.?//; s/[^A-Za-z0-9_-]+/-/g')"
NAME="outlayer-worker-${SUFFIX:-default}"
UNIT="/etc/systemd/system/$NAME.service"
ENV_COPY="/etc/outlayer-worker/$NAME.env"

if [[ "$ACTION" == stop ]]; then
  systemctl disable --now "$NAME" 2>/dev/null || true
  rm -f "$UNIT" "$ENV_COPY"
  systemctl daemon-reload
  echo "✓ $NAME stopped and removed"
  exit 0
fi
[[ "$ACTION" == start ]] || die "unknown action '$ACTION' (start | stop)"

BIN="$WORKER_DIR/target/release/offchainvm-worker"
[[ -x "$BIN" ]] || die "$BIN not built: cd worker && cargo build --release"
RUN_AS="$(stat -c %U "$WORKER_DIR")"
[[ "$RUN_AS" != root ]] || die "$WORKER_DIR belongs to root: a worker fetches untrusted input and never runs as root — chown the checkout to its own user"

# Read as the owner, written by root: a symlink in worker/ reaches only what the
# owner could read anyway.
install -d -m 0700 /etc/outlayer-worker
runuser -u "$RUN_AS" -- cat "$WORKER_DIR/$ENV_FILE" > "$ENV_COPY.new" \
  || { rm -f "$ENV_COPY.new"; die "cannot read $WORKER_DIR/$ENV_FILE as $RUN_AS"; }
chmod 0600 "$ENV_COPY.new"
mv "$ENV_COPY.new" "$ENV_COPY"

cat > "$UNIT" <<EOF
# Created by scripts/worker_service.sh from worker/$ENV_FILE.
[Unit]
Description=OutLayer worker $NAME
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_AS
WorkingDirectory=$WORKER_DIR
EnvironmentFile=$ENV_COPY
Environment=RUST_LOG=offchainvm_worker=info
ExecStart=$BIN
Restart=always
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$NAME" >/dev/null 2>&1
systemctl restart "$NAME"
sleep 2
systemctl --no-pager --lines=0 status "$NAME" | grep -E "^●|Active:"
echo "Logs: journalctl -u $NAME -f"
