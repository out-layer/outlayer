#!/usr/bin/env bash
#
# Mac-side orchestrator: deploy a self-hosted TDX worker END-TO-END from your laptop,
# mirroring scripts/deploy_phala.sh. Unlike Phala (cloud API reachable from anywhere), the
# CVM is created on the node (vmm is loopback-only there), so this SSHes to the node to
# deploy/restart, and signs the owner measurement-approval LOCALLY — the owner key stays on
# your Mac (never on the worker node, which could otherwise approve a rogue measurement).
#
# Usage:
#   ./scripts/deploy_tdx.sh worker   <testnet|mainnet> [instance-name] --version <ver> --node <ssh> [opts]
#   ./scripts/deploy_tdx.sh keystore <testnet|mainnet> [instance-name] --version <ver> --node <ssh> [opts]
#
# Required:
#   --version <ver>     release, e.g. 0.1.35
#   --node <ssh>        SSH target for the TDX node (lands as root/sudoer), e.g. root@173.237.9.76
#   --execute-excludes  worker only: routes this node must not run, e.g.
#                       "connectors.outlayer.near/polymarket:order". Omit it and the
#                       per-node table in this script decides (see node_excludes).
# Optional:
#   [instance-name]     CVM VM label (default outlayer-<component>-<net>-<ver>-1)
#   --digest <sha256>   image digest override (else resolved + attested locally via gh)
#   --remote-user <u>   run node commands as this user (default: outlayer; '' = don't su)
#   --remote-dir <d>    node clone of self-hosted-tdx (default: /home/outlayer/self-hosted-tdx)
#   --gateway-url <url> keystore only: per-VM dstack-gateway URL (e.g.
#                       https://gateway.dstack.outlayer.ai:9202). Set -> keystore deploys
#                       gateway-enabled and gets a public HTTPS endpoint
#                       https://<keystore-app-id>-8081.<domain>. Unset -> loopback-only keystore.
#   --os-image <img>    UPGRADE instead of deploy: move the EXISTING CVM [instance-name] to this
#                       dstack guest OS image (e.g. dstack-0.5.12, added to the node by
#                       deploy/self-hosted-tdx/15-add-os-image.sh), then approve its new
#                       measurements exactly as a deploy would. The CVM keeps its app-id, URL,
#                       disk and env; its measurements change. The container digest step is
#                       skipped (the container does not change); --version only names the
#                       instance when [instance-name] is omitted.
#   --kms-url <url>     deploy against this KMS instead of the node's default (KMS v1):
#                       https://kms-v2.<site>.dstack.outlayer.ai:11102 for KMS v2. Changes the
#                       measurements (RTMR3 carries the KMS), approved like any other.
#   --dry-run           show what would happen; no deploy, no tx
#
# The node deploys from ITS OWN copy of deploy/self-hosted-tdx, not from this checkout: the
# compose file, the env-file layout and the node-side deploy_tdx.sh are read there. This script
# does not copy that tree. After any change under deploy/self-hosted-tdx, ship it first:
#   ./deploy/self-hosted-tdx/sync-node.sh <host>
# then run this. A change that is only here deploys the node's old files, and nothing fails:
# a variable this script writes to the node's env file (EXECUTE_EXCLUDES) never reaches a
# container whose compose does not pass it on.
#
# Measurements are approved ONCE per (network, version): the measured compose-name is stable
# (outlayer-<component>-<net>-<ver>), so re-runs / extra instances of the same version hit the
# idempotent is_measurements_approved check and skip.
#
# worker:   deploy -> read measurements -> owner-approve on the register-contract -> wait for the
#           worker to register by itself (restarted only if it gave up waiting). Owner key stays
#           on the Mac.
# keystore: deploy (self-submits its DAO registration) -> read measurements -> owner-approve on
#           the DAO contract -> wait for the keystore's "Proposal ID: N" -> vote as zavodil
#           (auto on testnet, printed for manual run on mainnet) -> poll /health until ready.
#           Owner + zavodil keys stay on the Mac.
#
# Examples:
#   ./scripts/deploy_tdx.sh worker   testnet --version 0.1.35 --node root@173.237.9.76
#   ./scripts/deploy_tdx.sh worker   testnet worker-b --version 0.1.35 --node root@173.237.9.76
#   ./scripts/deploy_tdx.sh keystore testnet --version 0.1.35 --node root@173.237.9.76
set -euo pipefail

DEPLOY_VERSION=""; NODE=""; DIGEST=""; DRY_RUN=false; GATEWAY_URL=""; OS_IMAGE=""; KMS_URL=""
EXECUTE_EXCLUDES=""; EXCLUDES_SET=false
REMOTE_USER="outlayer"; REMOTE_DIR="/home/outlayer/self-hosted-tdx"
POS=()
while [[ $# -gt 0 ]]; do case "$1" in
  --version)     DEPLOY_VERSION="${2:?}"; shift 2;;
  --node)        NODE="${2:?}"; shift 2;;
  --digest)      DIGEST="${2:?}"; shift 2;;
  --remote-user) REMOTE_USER="${2-}"; shift 2;;
  --remote-dir)  REMOTE_DIR="${2:?}"; shift 2;;
  # keystore only: per-VM dstack-gateway URL. Set -> keystore deploys gateway-enabled (public HTTPS
  # https://<keystore-app-id>-8081.<domain>). Forwarded to the node as GATEWAY_URL=...
  --gateway-url) GATEWAY_URL="${2:?}"; shift 2;;
  # upgrade the existing CVM's guest OS image in place instead of deploying (see the header)
  --os-image)    OS_IMAGE="${2:?}"; shift 2;;
  # the KMS the CVM gets its keys from (default: the node script's, KMS v1); KMS v2 is
  # https://kms-v2.<site>.dstack.outlayer.ai:11102 (deploy/self-hosted-tdx/30-deploy-kms-v2.sh)
  --kms-url)     KMS_URL="${2:?}"; shift 2;;
  # worker only: routes this node must NOT run, `<project>:<operation>` or
  # `<project>:*`, comma-separated. Given here it overrides the per-node table
  # below; an empty string forces "no exclusions" on a node the table covers.
  --execute-excludes) EXECUTE_EXCLUDES="${2-}"; EXCLUDES_SET=true; shift 2;;
  --dry-run|--info) DRY_RUN=true; shift;;
  *) POS+=("$1"); shift;;
esac; done
COMPONENT="${POS[0]:-}"; NETWORK="${POS[1]:-testnet}"; INSTANCE_NAME="${POS[2]:-}"

case "$COMPONENT" in worker|keystore) ;; *) echo "component must be worker|keystore (got '$COMPONENT')" >&2; exit 1;; esac
case "$NETWORK" in testnet|mainnet) ;; *) echo "network must be testnet|mainnet (got '$NETWORK')" >&2; exit 1;; esac
[ -n "$DEPLOY_VERSION" ] || { echo "--version <ver> required (e.g. --version 0.1.35)" >&2; exit 1; }
[ -n "$NODE" ] || { echo "--node <ssh-target> required (e.g. --node root@173.237.9.76)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Routes a node cannot run, by node.
#
# A venue can refuse one of our nodes and serve the others: Polymarket's CLOB
# answers order placement with `403 Trading restricted in your region` to a US
# address while serving its reads, its cancels and its relayer from everywhere
# (measured 2026-09-11 from both nodes). The worker passes this list to the
# coordinator on every poll, and the coordinator hands those calls to a node
# that can run them, so a guest never sees a failure its placement could have
# avoided.
#
# Keyed by the HOST of `--node`, because that is what the operator types. Keep
# it in step with where the nodes actually are: a node that moves country needs
# its row changed, and nothing in the deploy can notice that for you.
# Answers one of three things, and the difference matters:
#   a rule list   this node refuses those routes
#   `none`        this node is KNOWN to refuse nothing, so a stale value on it
#                 is cleared
#   empty         this node is not in the table at all, so whatever the operator
#                 set by hand is left exactly as it is
node_excludes() {
  # $SUFFIX is near|testnet and is set before this is ever called, so a rule
  # names the project of the network being deployed.
  local pm="connectors.outlayer.$SUFFIX/polymarket"
  case "${1#*@}" in
    # Dallas, Texas — US. Polymarket's edge refuses ORDER PLACEMENT from here
    # (measured 2026-09-11: only `POST /order` and `POST /orders` answer 403;
    # reads, credential derivation, cancels, the relayer and the bridge all
    # behave the same as from Europe). Only the operation that places an order
    # is excluded — excluding a read would make this node wait for another one
    # to answer something it can answer itself.
    173.237.9.76) echo "$pm:order" ;;
    # Haarlem — NL. Nothing known to refuse it.
    23.109.254.164) echo "none" ;;
    # A node nobody has measured: left alone rather than guessed at.
    *) echo "" ;;
  esac
}

VER="${DEPLOY_VERSION#v}"
SUFFIX=$([ "$NETWORK" = mainnet ] && echo near || echo testnet)
OWNER="owner.outlayer.$SUFFIX"
# Per-component config:
#   IMAGE   = Docker Hub image (also the GitHub-release digest row label, lowercased).
#   NAME    = per-instance CVM VM label (lsvm / worker-ctl.sh).
#   worker:   measurements + registration live on the register-contract worker.outlayer.<net>.
#   keystore: governance lives on the DAO dao.outlayer.<net>; the keystore container is
#             dstack-keystore-1 (worker-ctl.sh defaults to dstack-worker-1, so we pass CONTAINER).
case "$COMPONENT" in
  worker)
    IMAGE="outlayer/near-outlayer-worker"
    REGISTER="worker.outlayer.$SUFFIX"
    NAME="${INSTANCE_NAME:-outlayer-worker-${NETWORK}-${VER}-1}"
    ;;
  keystore)
    IMAGE="outlayer/near-outlayer-keystore"
    DAO="dao.outlayer.$SUFFIX"
    VOTER="zavodil.$SUFFIX"
    KS_CONTAINER="dstack-keystore-1"
    NAME="${INSTANCE_NAME:-outlayer-keystore-${NETWORK}-${VER}-1}"
    ;;
esac

# The five measurements of the CVM named $NAME, as the contract-argument JSON, read from its
# guest agent's tcb_info over the node loopback (worker-ctl.sh finds the port). Empty while the
# CVM is not up yet. Any booted CVM answers, registered or not, worker or keystore.
agent_measurements() {
  node_run "p=\$(NAME=$NAME ./worker-ctl.sh port 2>/dev/null); case \"\$p\" in ''|'<'*) exit 0;; esac; \
    curl -s --max-time 5 \"http://127.0.0.1:\$p/prpc/Info?json\" | python3 -c '
import sys, json
t = json.loads(json.load(sys.stdin)[\"tcb_info\"])
m = {k: t[k] for k in (\"mrtd\", \"rtmr0\", \"rtmr1\", \"rtmr2\", \"rtmr3\")}
assert all(len(v) == 96 for v in m.values())
print(json.dumps(m, separators=(\",\", \":\")))' 2>/dev/null" 2>/dev/null | grep -oE '^\{"mrtd":"[a-f0-9]{96}".*\}$' | tail -1
}

# Run a command on the node as REMOTE_USER inside REMOTE_DIR. base64 avoids all quoting hell.
node_run() {
  local cmd b64
  cmd="cd '$REMOTE_DIR' && $*"
  b64=$(printf '%s' "$cmd" | base64 | tr -d '\n')
  if [ -n "$REMOTE_USER" ]; then
    ssh "$NODE" "su - '$REMOTE_USER' -c 'echo $b64 | base64 -d | bash'"
  else
    ssh "$NODE" "echo $b64 | base64 -d | bash"
  fi
}

echo "== deploy_tdx: $COMPONENT $NETWORK  vm-label=$NAME  version=v$VER  node=$NODE =="

# [1/N] resolve + attest the image digest locally (the node has no gh). The GitHub release
# body lists one row per component: `| worker | sha256:... |`, `| keystore | sha256:... |`.
if [ -n "$OS_IMAGE" ]; then
  echo "[1] OS image upgrade of the existing CVM '$NAME' to $OS_IMAGE: the container is not redeployed, no digest to resolve"
elif [ -z "$DIGEST" ]; then
  echo "[1] Resolve $COMPONENT digest for v$VER (gh, local)..."
  DIGEST=$(gh release view "v$VER" --repo out-layer/outlayer --json body -q '.body' 2>/dev/null \
    | grep -iE "\\| *$COMPONENT *\\|" | grep -oE 'sha256:[a-f0-9]{64}' | head -1) || true
  [ -n "$DIGEST" ] || { echo "  Could not resolve digest via gh — pass --digest sha256:..." >&2; exit 1; }
fi
[ -n "$OS_IMAGE" ] || echo "  digest: $DIGEST"
if [ -z "$OS_IMAGE" ] && command -v gh >/dev/null 2>&1; then
  # Releases up to v0.1.58 are attested under the fastnear GitHub organization (the
  # repository former home), so fall back to --owner fastnear when the repo lookup fails.
  if gh attestation verify "oci://docker.io/$IMAGE@$DIGEST" -R out-layer/outlayer >/dev/null 2>&1; then
    echo "  Sigstore attestation: verified (out-layer/outlayer)"
  elif gh attestation verify "oci://docker.io/$IMAGE@$DIGEST" --owner fastnear >/dev/null 2>&1; then
    echo "  Sigstore attestation: verified (owner fastnear, pre-v0.1.59 release)"
  else
    echo "  Sigstore attestation: NOT verified (continuing — verify manually before trusting)"
  fi
fi

if $DRY_RUN; then
  if [ -n "$OS_IMAGE" ]; then
    gate=$([ "$COMPONENT" = worker ] && echo "approve on $REGISTER (signer $OWNER) -> wait for it to register" || echo "approve on $DAO (signer $OWNER) -> wait for proposal -> vote (signer $VOTER) -> poll /health")
    echo "(dry-run) would: on $NODE, worker-ctl.sh set-image $NAME $OS_IMAGE (soft stop, resize --image, start) -> read measurements -> $gate"
    exit 0
  fi
  if [ "$COMPONENT" = worker ]; then
    echo "(dry-run) would: deploy CVM '$NAME' on $NODE${KMS_URL:+ (kms-url=$KMS_URL)} -> read measurements -> approve on $REGISTER (signer $OWNER) -> wait for it to register"
    if [ "$EXCLUDES_SET" = true ]; then
      echo "(dry-run) would set in $REMOTE_DIR/worker/.env.${NETWORK}-worker-tdx: EXECUTE_EXCLUDES=${EXECUTE_EXCLUDES:-<empty>} (from --execute-excludes)"
    else
      case "$(node_excludes "$NODE")" in
        "")   echo "(dry-run) $NODE is not in the per-node table: EXECUTE_EXCLUDES left exactly as it is on the node" ;;
        none) echo "(dry-run) would CLEAR EXECUTE_EXCLUDES in $REMOTE_DIR/worker/.env.${NETWORK}-worker-tdx (the table knows this node refuses nothing)" ;;
        *)    echo "(dry-run) would set in $REMOTE_DIR/worker/.env.${NETWORK}-worker-tdx: EXECUTE_EXCLUDES=$(node_excludes "$NODE")" ;;
      esac
    fi
  else
    echo "(dry-run) would: deploy CVM '$NAME' on $NODE${GATEWAY_URL:+ (gateway-url=$GATEWAY_URL)} -> read measurements -> approve on $DAO (signer $OWNER) -> wait for proposal -> vote (signer $VOTER) -> poll /health"
  fi
  exit 0
fi

if [ "$COMPONENT" = worker ]; then
# The node's clock before this deploy boots anything: [5/5] counts only log lines from here on.
W_SINCE=$(node_run "date -u +%Y-%m-%dT%H:%M:%S" 2>/dev/null | tail -1 | tr -d '\r')
[[ "$W_SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}$ ]] || { echo "  could not read the node's clock (got '$W_SINCE')" >&2; exit 1; }
if [ -n "$OS_IMAGE" ]; then
# [2/5] upgrade: the existing CVM boots the new guest OS; env, disk and app-id are untouched
echo "[2/5] Move CVM '$NAME' to $OS_IMAGE on the node (soft stop, resize --image, start)..."
node_run "./worker-ctl.sh set-image $NAME $OS_IMAGE"
else
# [2/5] deploy the CVM on the node (node-side deploy_tdx.sh derives the stable COMPOSE_NAME)
echo "[2/5] Deploy CVM on node (reads node env: $REMOTE_DIR/worker/.env.${NETWORK}-worker-tdx — NOT your local copy)..."

# EXECUTE_EXCLUDES lands in the NODE's env file, which is what the CVM reads.
# `--execute-excludes` wins; otherwise the table above decides, and a node the
# table does not cover is left exactly as the operator last set it — this
# script never silently erases a value somebody put there by hand.
WANT_EXCLUDES=""
WRITE_EXCLUDES=false
if [ "$EXCLUDES_SET" = true ]; then
  # `--execute-excludes ""` is a deliberate "refuse nothing", so it writes.
  WANT_EXCLUDES="$EXECUTE_EXCLUDES"; WRITE_EXCLUDES=true
else
  case "$(node_excludes "$NODE")" in
    "")      WRITE_EXCLUDES=false ;;
    none)    WANT_EXCLUDES=""; WRITE_EXCLUDES=true ;;
    *)       WANT_EXCLUDES="$(node_excludes "$NODE")"; WRITE_EXCLUDES=true ;;
  esac
fi
if [ "$WRITE_EXCLUDES" = true ]; then
  ENV_FILE="$REMOTE_DIR/worker/.env.${NETWORK}-worker-tdx"
  WAS=$(node_run "grep -m1 '^EXECUTE_EXCLUDES=' '$ENV_FILE' 2>/dev/null | cut -d= -f2- || true" 2>/dev/null | tr -d '\r')
  # Sent as base64, so operator text never becomes part of a sed replacement
  # (where `&` means the whole match) or of a shell word on the node.
  EXCLUDES_B64=$(printf '%s' "$WANT_EXCLUDES" | base64 | tr -d '\n')
  SET_OUT=$(node_run "set -e
    f='$ENV_FILE'
    if [ ! -f \"\$f\" ]; then echo MISSING; exit 0; fi
    v=\$(printf %s '$EXCLUDES_B64' | base64 -d)
    { grep -v '^EXECUTE_EXCLUDES=' \"\$f\" || true; } > \"\$f.tmp\"
    printf 'EXECUTE_EXCLUDES=%s\n' \"\$v\" >> \"\$f.tmp\"
    cat \"\$f.tmp\" > \"\$f\"
    rm -f \"\$f.tmp\"
    echo OK" 2>&1 | tail -1 | tr -d '\r')
  if [ "$SET_OUT" = MISSING ]; then
    echo "  !! $ENV_FILE not found on the node. EXECUTE_EXCLUDES not set, and the deploy below reads the same file."
  elif [ "$SET_OUT" != OK ]; then
    echo "  !! could not set EXECUTE_EXCLUDES on the node: $SET_OUT" >&2
    exit 1
  elif [ -z "$WANT_EXCLUDES" ]; then
    echo "  routes this node refuses: none${WAS:+ (cleared; was: $WAS)}"
  else
    echo "  routes this node refuses: $WANT_EXCLUDES"
    echo "    those venues refuse this node's address; the coordinator gives such calls to another node"
    [ -n "$WAS" ] && [ "$WAS" != "$WANT_EXCLUDES" ] && echo "    previous value on the node: $WAS"
  fi
fi
node_run "${KMS_URL:+KMS_URL=$KMS_URL }WORKER_DIGEST=$DIGEST ./deploy_tdx.sh worker $NETWORK $NAME --version $VER"
fi  # deploy vs --os-image

# [3/5] read the 5 TEE measurements. Source of truth: the CVM's guest agent (tcb_info on its
# loopback port), which answers for any booted CVM. The worker's own log carries them only on a
# boot that registers a key, so a CVM whose key is already registered (an OS image upgrade)
# logs nothing — the log is the fallback, not the source.
echo "[3/5] Read TEE measurements from the CVM's guest agent (waiting for boot)..."
MEAS=""
for i in $(seq 1 20); do
  MEAS=$(agent_measurements || true)
  [ -n "$MEAS" ] && break
  LOGS=$(node_run "NAME=$NAME TAIL=600 ./worker-ctl.sh logs" 2>/dev/null || true)
  MRTD=$(printf '%s' "$LOGS" | grep -oE 'MRTD:[[:space:]]+[a-f0-9]{96}' | tail -1 | grep -oE '[a-f0-9]{96}' || true)
  if [ -n "$MRTD" ]; then
    rd(){ printf '%s' "$LOGS" | grep -oE "$1:[[:space:]]+[a-f0-9]{96}" | tail -1 | grep -oE '[a-f0-9]{96}'; }
    MEAS=$(printf '{"mrtd":"%s","rtmr0":"%s","rtmr1":"%s","rtmr2":"%s","rtmr3":"%s"}' "$MRTD" "$(rd RTMR0)" "$(rd RTMR1)" "$(rd RTMR2)" "$(rd RTMR3)")
    break
  fi
  sleep 12
done
[ -n "$MEAS" ] || { echo "  Could not read measurements after ~4min. Check: NAME=$NAME worker-ctl.sh follow" >&2; exit 1; }
MRTD=$(printf '%s' "$MEAS" | grep -oE '"mrtd":"[a-f0-9]{96}"' | grep -oE '[a-f0-9]{96}')
RTMR3=$(printf '%s' "$MEAS" | grep -oE '"rtmr3":"[a-f0-9]{96}"' | grep -oE '[a-f0-9]{96}')
echo "  mrtd=$MRTD"
echo "  rtmr3=$RTMR3"

# [4/5] approve measurements on the register-contract (idempotent; owner key local)
echo "[4/5] Approve measurements on $REGISTER (signer $OWNER)..."
APPROVED=$(near contract call-function as-read-only "$REGISTER" is_measurements_approved \
  json-args "{\"measurements\":$MEAS}" network-config "$NETWORK" now 2>/dev/null | tr -d '[:space:]' || true)
if printf '%s' "$APPROVED" | grep -qi true; then
  echo "  already approved — skipping (approve-once per net+version)"
else
  near contract call-function as-transaction "$REGISTER" add_approved_measurements \
    json-args "{\"measurements\":$MEAS,\"clear_others\":false}" \
    prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$OWNER" network-config "$NETWORK" sign-with-legacy-keychain send
  echo "  measurements approved"
fi

# [5/5] wait for the worker to register. It polls is_measurements_approved every 5 s for ~8 min
# (registration.rs wait_for_measurements_approval) and registers by itself once [4/5] approved,
# so no restart is needed. Only a worker that gave up (approval later than its window: the
# process exits) is restarted, once. A worker whose key is already on the contract (an OS image
# upgrade keeps the disk, and the key on it) does not register again: it logs "Key registered and
# ready for signing". Only lines of this deploy's boots count ($W_SINCE): the container log
# survives a restart, and an earlier boot's success line says nothing about this one.
worker_watch() { # rounds of 12 s → 0 registered, 1 error (exits), 2 undecided
  local i L
  for i in $(seq 1 "$1"); do
    L=$(node_run "NAME=$NAME TAIL=400 ./worker-ctl.sh logs" 2>/dev/null \
      | awk -v t="$W_SINCE" '/^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ && substr($0, 1, 19) >= t' || true)
    if printf '%s' "$L" | grep -qE "Worker key registered successfully|Key registered and ready for signing"; then
      echo "  REGISTERED:"; printf '%s' "$L" | grep -E "registered successfully|Key registered and ready|Transaction:" | tail -2
      return 0
    fi
    if printf '%s' "$L" | grep -qiE "Exceeded the prepaid gas|did not verify|No cached collateral"; then
      echo "  registration error:"; printf '%s' "$L" | grep -iE "exceeded|verif|collateral" | tail -3 >&2; exit 1
    fi
    sleep 12
  done
  return 2
}
echo "[5/5] Wait for the worker to register (it does so by itself once the measurements are approved)..."
if worker_watch 45; then
  echo "Done. Manage: ssh $NODE -> su - $REMOTE_USER -> cd $REMOTE_DIR -> NAME=$NAME ./worker-ctl.sh follow"
  exit 0
fi
echo "  not registered within ~9 min (its approval window has passed): restarting it once..."
node_run "NAME=$NAME ./worker-ctl.sh restart" >/dev/null || true
if worker_watch 20; then
  echo "Done. Manage: ssh $NODE -> su - $REMOTE_USER -> cd $REMOTE_DIR -> NAME=$NAME ./worker-ctl.sh follow"
  exit 0
fi
echo "  No decisive result yet — check: NAME=$NAME worker-ctl.sh follow (on the node)"
exit 0
fi  # end worker

# ============================== keystore flow ==============================
# Unlike the worker (owner-approve -> it registers by itself), the keystore self-submits its DAO
# registration on boot (logs "Proposal ID: N"). Governance = owner-approve measurements on the
# DAO + a DAO member (zavodil) vote. Both signed LOCALLY (keys stay on the Mac).

# Logs come from the dstack-keystore-1 container (worker-ctl.sh defaults to dstack-worker-1).
ks_logs() { node_run "NAME=$NAME CONTAINER=$KS_CONTAINER TAIL=${1:-600} ./worker-ctl.sh logs"; }

# [2/6] deploy the CVM on the node (node-side deploy_tdx.sh derives the stable COMPOSE_NAME).
# GATEWAY_URL (optional) flows Mac --gateway-url -> node env -> 40-deploy-keystore.sh: when set, the
# keystore deploys gateway-enabled and gets a public HTTPS endpoint.
if [ -n "$OS_IMAGE" ]; then
# [2/6] upgrade: the existing keystore boots the new guest OS; app-id, URL, disk, env and the
# gateway registration are untouched. It is not ready from the stop until the vote lands.
echo "[2/6] Move CVM '$NAME' to $OS_IMAGE on the node (soft stop, resize --image, start)..."
node_run "./worker-ctl.sh set-image $NAME $OS_IMAGE"
KEYSTORE_URL=""   # unchanged by an image upgrade; nothing new to announce
else
echo "[2/6] Deploy CVM on node (reads node env: $REMOTE_DIR/keystore/.env.${NETWORK}-keystore-tdx — NOT your local copy)..."
if [ -n "$GATEWAY_URL" ]; then
  echo "  gateway mode: GATEWAY_URL=$GATEWAY_URL"
else
  echo "  WARNING: no --gateway-url given -> deploying a PLAIN (loopback-only) keystore."
  echo "           It registers + serves on the node, but has NO public endpoint: the gateway URL"
  echo "           https://<app-id>-8081.<gateway-domain> will NOT route to it (404)."
  echo "           For a public TEE-terminated endpoint, pass: --gateway-url https://gateway.<domain>:9202"
fi
# Capture the node deploy output (tee'd so the operator still sees it) to recover the gateway-mode
# KEYSTORE_URL=... line that 40-deploy-keystore.sh prints (app-id is computed node-side from
# the final app-compose). Empty in plain mode.
DEPLOY_LOG=$(node_run "${KMS_URL:+KMS_URL=$KMS_URL }GATEWAY_URL='$GATEWAY_URL' WORKER_DIGEST=$DIGEST ./deploy_tdx.sh keystore $NETWORK $NAME --version $VER" 2>&1 | tee /dev/stderr) || true
KEYSTORE_URL=$(printf '%s' "$DEPLOY_LOG" | grep -oE 'KEYSTORE_URL=https://[^[:space:]]+' | tail -1 | sed 's/^KEYSTORE_URL=//' || true)
fi  # deploy vs --os-image

# [3/6] read the 5 TEE measurements from the keystore's logs.
# The keystore logs them as a single DEBUG line: "TDX Measurements: MRTD=<hex>, RTMR0=<hex>, ..."
# (comma-separated KEY=hex — NOT the worker's "MRTD:  <hex>" colon form). RUST_LOG includes
# keystore_worker=debug so the line is emitted.
#
# B1: that line is printed ONCE per boot (tdx_attestation.rs call_phala_dstack_socket, debug). The
# old TAIL=600 window was too small — on a chatty boot the line scrolls past it and the grep finds
# nothing -> a false abort. Fix: (a) capture a MUCH larger window (KS_MEAS_TAIL=8000), and (b) force
# a clean restart FIRST so the once-per-boot line is freshly near the tail of the captured window
# (it's the same kind of restart the flow already does before grepping the Proposal ID). Robust under
# set -euo pipefail: worker-ctl.sh restart is best-effort (|| true), then we poll.
# The guest agent is the source (see agent_measurements); the log line is the fallback.
KS_MEAS_TAIL="${KS_MEAS_TAIL:-8000}"
echo "[3/6] Read TEE measurements from the CVM's guest agent (waiting for boot)..."
MEAS=""
for i in $(seq 1 20); do
  MEAS=$(agent_measurements || true)
  [ -n "$MEAS" ] && break
  LOGS=$(ks_logs "$KS_MEAS_TAIL" 2>/dev/null || true)
  MRTD=$(printf '%s' "$LOGS" | grep -oE 'MRTD=[a-f0-9]{96}' | tail -1 | grep -oE '[a-f0-9]{96}' || true)
  if [ -n "$MRTD" ]; then
    rd(){ printf '%s' "$LOGS" | grep -oE "$1=[a-f0-9]{96}" | tail -1 | grep -oE '[a-f0-9]{96}'; }
    MEAS=$(printf '{"mrtd":"%s","rtmr0":"%s","rtmr1":"%s","rtmr2":"%s","rtmr3":"%s"}' "$MRTD" "$(rd RTMR0)" "$(rd RTMR1)" "$(rd RTMR2)" "$(rd RTMR3)")
    break
  fi
  sleep 12
done
[ -n "$MEAS" ] || { echo "  Could not read measurements after ~4min. Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow" >&2; exit 1; }
MRTD=$(printf '%s' "$MEAS" | grep -oE '"mrtd":"[a-f0-9]{96}"' | grep -oE '[a-f0-9]{96}')
RTMR3=$(printf '%s' "$MEAS" | grep -oE '"rtmr3":"[a-f0-9]{96}"' | grep -oE '[a-f0-9]{96}')
echo "  mrtd=$MRTD"
echo "  rtmr3=$RTMR3"

# [4/6] approve measurements on the DAO contract (idempotent; owner key local)
echo "[4/6] Approve measurements on $DAO (signer $OWNER)..."
# M1: parse the bool strictly (the old `grep -qi true` over full near-cli-rs output is fragile — it
# matches "true" anywhere in the noisy output). Mirror the stricter phala form: pull the FIRST
# true|false token and compare exactly.
APPROVED=$(near contract call-function as-read-only "$DAO" is_measurements_approved \
  json-args "{\"measurements\":$MEAS}" network-config "$NETWORK" now 2>/dev/null \
  | grep -oiE 'true|false' | head -1 || true)
if [ "$APPROVED" = true ]; then
  echo "  already approved — skipping (approve-once per net+version)"
else
  near contract call-function as-transaction "$DAO" add_approved_measurements \
    json-args "{\"measurements\":$MEAS,\"clear_others\":false}" \
    prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$OWNER" network-config "$NETWORK" sign-with-legacy-keychain send
  echo "  measurements approved"
fi

# [5/6] wait for the keystore's self-submitted proposal, then vote as zavodil.
# Measurements are approved now, so if the keystore had already submitted (and the DAO rejected
# for not-approved) it will resubmit on the next boot. Restart once to force a clean submit
# against the now-approved list, then grep for the Proposal ID.
echo "[5/6] Restart keystore so it submits against the approved measurements..."
# The keystore mints a new registration key on EVERY boot and submits a proposal for it, and
# the container log survives the restart. So only what the keystore logs AFTER this restart
# counts: a proposal or a "ready" line from before it belongs to a key the keystore no longer
# holds, and a vote on such a proposal executes, changes nothing, and leaves the live key waiting
# until its 30-min registration timeout. A boot that is still registering when the restart is
# issued can submit after any "highest id so far" was read, so the cut is the node's clock taken
# once the restart has returned (the old VM is down by then); the proposal is then checked on
# chain against the key the new boot announced.
node_run "NAME=$NAME ./worker-ctl.sh restart" >/dev/null || true
SINCE=$(node_run "date -u +%Y-%m-%dT%H:%M:%S" 2>/dev/null | tail -1 | tr -d '\r')
[[ "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}$ ]] || { echo "  could not read the node's clock (got '$SINCE')" >&2; exit 1; }
echo "  counting only what the keystore logs from $SINCE UTC on"
# The keystore's log lines from $SINCE on (they start with an ISO timestamp).
ks_logs_since() { ks_logs "${1:-600}" 2>/dev/null | awk -v t="$SINCE" '/^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ && substr($0, 1, 19) >= t'; }
echo "  waiting for the keystore to submit its DAO proposal (Proposal ID: N)..."
PROPOSAL_ID=""; LIVE_KEY=""
for i in $(seq 1 25); do
  L=$(ks_logs_since 600 || true)
  LIVE_KEY=$(printf '%s' "$L" | grep -oE 'Using keystore public key: [a-z0-9-]+:[A-Za-z0-9]+' | tail -1 | sed 's/.*: //' || true)
  # main.rs logs "Proposal ID: {}" on a successful submit; tee_registration.rs logs the same.
  PROPOSAL_ID=$(printf '%s' "$L" | grep -oE 'Proposal ID: [0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1 || true)
  if [ -n "$PROPOSAL_ID" ]; then
    P=$(near contract call-function as-read-only "$DAO" get_proposal json-args "{\"proposal_id\":$PROPOSAL_ID}" \
      network-config "$NETWORK" now 2>/dev/null || true)
    P_KEY=$(printf '%s' "$P" | grep -oE '"public_key": "[^"]+"' | head -1 | sed -E 's/.*: "([^"]+)"/\1/')
    P_STATUS=$(printf '%s' "$P" | grep -oE '"status": "[A-Za-z]+"' | head -1 | sed -E 's/.*: "([^"]+)"/\1/')
    if [ -z "$LIVE_KEY" ] || [ "$P_KEY" != "$LIVE_KEY" ] || [ "$P_STATUS" != Pending ]; then
      echo "  #$PROPOSAL_ID is not the live key's pending proposal yet (key ${P_KEY:-?}, live ${LIVE_KEY:-not logged yet}, status ${P_STATUS:-?}); waiting"
      PROPOSAL_ID=""
    fi
  fi
  [ -n "$PROPOSAL_ID" ] && break
  # Do NOT early-exit on "measurements not approved" / "Registration rejected": that line is EXPECTED
  # from the keystore's FIRST boot (before [4/6] approved) and persists in the log buffer, so bailing
  # on it is a false negative — the keystore retries (container `restart: on-failure`) and submits a
  # proposal once the measurements are approved. The ~5min timeout below catches a genuine failure.
  sleep 12
done
[ -n "$PROPOSAL_ID" ] || { echo "  No 'Proposal ID' in logs after ~5min. Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow" >&2; exit 1; }
echo "  proposal id: $PROPOSAL_ID (live key $LIVE_KEY, pending on $DAO)"

# Vote: auto on testnet, manual on mainnet (mirror deploy_phala.sh step 7 — a human turns the
# mainnet key). Threshold with the single member zavodil is 1, so one approve passes it.
VOTE_ARGS="{\"proposal_id\":$PROPOSAL_ID,\"approve\":true}"
if [ "$NETWORK" = mainnet ]; then
  echo "  MAINNET — vote manually to approve proposal #$PROPOSAL_ID:"
  echo ""
  echo "    near contract call-function as-transaction $DAO vote \\"
  echo "      json-args '$VOTE_ARGS' \\"
  echo "      prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \\"
  echo "      sign-as $VOTER network-config $NETWORK sign-with-legacy-keychain send"
  echo ""
  echo "  After the vote lands, the keystore pulls its MPC-CKD master and becomes ready."
  echo "  Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow (on the node)"
  if [ -n "$KEYSTORE_URL" ]; then
    echo ""
    echo "  Once READY, the public endpoint (via dstack-gateway) is:"
    echo "    $KEYSTORE_URL"
    echo "  Add it to the comma-separated KEYSTORE_BASE_URLS in the worker env and the coordinator env."
  fi
  exit 0
fi
echo "  Voting on proposal #$PROPOSAL_ID as $VOTER..."
near contract call-function as-transaction "$DAO" vote \
  json-args "$VOTE_ARGS" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$VOTER" network-config "$NETWORK" sign-with-legacy-keychain send
echo "  voted"

# [6/6] poll the keystore until it is READY. /health returns 200 unconditionally (it does NOT
# reflect is_ready), so 200 only proves the server is UP. The authoritative readiness signal is
# the log line "✅ TEE registration complete! Keystore is now ready to serve requests" (main.rs).
# We confirm liveness via the loopback KS port AND readiness via that log line.
echo "[6/6] Wait for the keystore to finish TEE registration + become ready..."
for i in $(seq 1 25); do
  # Loopback liveness probe through the node (the KS port is 127.0.0.1-only on the node). The
  # keystore port -> guest 8081 is read from the live qemu cmdline, same as worker-ctl's agent_port.
  HEALTH=$(node_run "set -e; u=\$(NAME=$NAME ./worker-ctl.sh uuid); \
    p=\$(for pid in \$(pgrep -f qemu-system-x86_64); do c=\$(tr '\\0' ' ' < /proc/\$pid/cmdline 2>/dev/null) || continue; \
      [[ \"\$c\" == *\"\$u\"* ]] || continue; echo \"\$c\" | grep -oE '127\\.0\\.0\\.1:[0-9]+-:8081' | sed -E 's/.*:([0-9]+)-:8081/\\1/' | head -1; break; done); \
    [ -n \"\$p\" ] && curl -fs --max-time 5 \"http://127.0.0.1:\$p/health\" || true" 2>/dev/null || true)
  # Only a "ready" line of THIS boot counts (see [5/6]): an earlier boot's line survives in the log.
  L=$(ks_logs_since 600 || true)
  if printf '%s' "$L" | grep -q "Keystore is now ready to serve requests"; then
    echo "  READY: keystore completed TEE registration + pulled its MPC-CKD master."
    [ -n "$HEALTH" ] && echo "  /health (loopback): $HEALTH"
    echo "Done. Manage: ssh $NODE -> su - $REMOTE_USER -> cd $REMOTE_DIR -> NAME=$NAME CONTAINER=$KS_CONTAINER ./worker-ctl.sh follow"
    if [ -n "$KEYSTORE_URL" ]; then
      echo ""
      echo "  PUBLIC ENDPOINT (via dstack-gateway, TLS terminates in the TEE):"
      echo "    $KEYSTORE_URL"
      echo "  Add it to the comma-separated KEYSTORE_BASE_URLS in the worker env and the coordinator env."
    elif [ -n "$OS_IMAGE" ]; then
      echo "  Endpoint unchanged: an OS image upgrade keeps the app-id, the URL and the gateway registration."
    else
      echo "NOTE: this exposes only a LOOPBACK port on the node. Public ingress (TLS-in-TEE gateway)"
      echo "needs gateway mode — re-run with --gateway-url <https://gateway.<domain>:9202> to get a"
      echo "public https://<keystore-app-id>-8081.<domain> endpoint."
    fi
    exit 0
  fi
  # Do NOT early-exit on "TEE registration failed" / "remain in not-ready": those lines are EXPECTED
  # from the keystore's pre-approval boot attempts and persist in the log buffer, so bailing on them is
  # a false negative — the keystore retries (container `restart: on-failure`) and, once the vote
  # executes, pulls its MPC-CKD master and logs "ready to serve requests". Wait for THAT (the timeout
  # below catches a genuine never-ready).
  sleep 12
done
echo "  Voted on #$PROPOSAL_ID but not READY yet — check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow (on the node)"
