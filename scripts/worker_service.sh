#!/usr/bin/env bash
# Run a worker as a systemd service instead of in a screen: the same binary and
# env file `run_worker.sh` uses, restarted on failure and on reboot, logs in
# journald.
#
# Build first (cd worker && cargo build --release), then, as root, from the
# repository root:
#
#   sudo ./scripts/worker_service.sh .env.mainnet.worker1     create + start
#   sudo ./scripts/worker_service.sh .env.mainnet.worker1 stop    stop + disable
#
# The service is named after the env file: `.env.mainnet.worker1` →
# `outlayer-worker-mainnet-worker1`. It runs as the owner of the checkout, with
# `worker/` as its working directory. After a rebuild:
# `systemctl restart outlayer-worker-<name>`.
set -euo pipefail

ENV_FILE="${1:?usage: sudo ./scripts/worker_service.sh <env file in worker/> [stop]}"
ACTION="${2:-start}"

[[ $EUID -eq 0 ]] || { echo "✗ run as root (sudo)" >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER_DIR="$REPO/worker"
SUFFIX="$(basename "$ENV_FILE" | sed -E 's/^\.env\.?//; s/[^A-Za-z0-9_-]+/-/g')"
NAME="outlayer-worker-${SUFFIX:-default}"
UNIT="/etc/systemd/system/$NAME.service"

if [[ "$ACTION" == stop ]]; then
  systemctl disable --now "$NAME" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  echo "✓ $NAME stopped and removed"
  exit 0
fi
[[ "$ACTION" == start ]] || { echo "✗ unknown action '$ACTION' (start | stop)" >&2; exit 1; }

BIN="$WORKER_DIR/target/release/offchainvm-worker"
[[ -f "$WORKER_DIR/$ENV_FILE" ]] || { echo "✗ $WORKER_DIR/$ENV_FILE not found" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "✗ $BIN not built: cd worker && cargo build --release" >&2; exit 1; }
RUN_AS="$(stat -c %U "$WORKER_DIR")"

cat > "$UNIT" <<EOF
# Created by scripts/worker_service.sh from $ENV_FILE.
[Unit]
Description=OutLayer worker ($ENV_FILE)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_AS
WorkingDirectory=$WORKER_DIR
EnvironmentFile=$WORKER_DIR/$ENV_FILE
Environment=RUST_LOG=offchainvm_worker=info
ExecStart=$BIN
Restart=always
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$NAME"
sleep 2
systemctl --no-pager --lines=0 status "$NAME" | grep -E "^●|Active:"
echo "Logs: journalctl -u $NAME -f"
