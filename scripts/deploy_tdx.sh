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
#   --node <ssh>        SSH target for the TDX node (lands as root/sudoer), e.g. root@$DAL_HOST
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
#                       measurements (RTMR3 carries the KMS), approved like any other. The
#                       <site> must be the node's own (see node_kms_site); refused otherwise.
#   --resume           continue with the CVM [instance-name] as it is deployed — no new deploy.
#                       keystore: the second run after its measurements were approved by DAO
#                       vote: a new deploy would be a new CVM with a new instance-id in RTMR3,
#                       whose measurements the approved ones no longer match.
#                       worker: run it any time after the deploy, as often as needed. It reads the
#                       CVM's measurements, says where their approval stands (the proposal, when it
#                       executes, the command that executes it), and once they are approved checks
#                       that the worker registered, restarting it only if it gave up waiting. No
#                       KMS check and no digest lookup: nothing is deployed.
#   --print            DAO steps send nothing: the ready propose / vote / execute commands are
#                       printed, one per member (DAO_CHAIN=print). Without it, on testnet, every DAO
#                       step is sent with the members' keys found in the local legacy keychain.
#                       Mainnet always prints.
#   --auto             testnet only, not with --print: a DAO step that waits for its delay (or
#                       for votes) is driven again every 65 s, up to 10 times, and the run goes on
#                       in-process as --resume would, so one command takes a worker through its
#                       measurements approval to its registration, and a keystore through the
#                       approval of its build, its registration vote and readiness. The waits run
#                       out -> the same next steps as without it, their --resume carrying --auto.
#   --dry-run          show what would happen; no deploy, no tx
#
# The node deploys from ITS OWN copy of deploy/self-hosted-tdx, not from this checkout: the
# compose file, the env-file layout and the node-side deploy_tdx.sh are read there. This script
# does not copy that tree. After any change under deploy/self-hosted-tdx, ship it first:
#   ./deploy/self-hosted-tdx/sync-node.sh <host>
# then run this. A change that is only here deploys the node's old files, and nothing fails:
# a variable this script writes to the node's env file (EXECUTE_EXCLUDES) never reaches a
# container whose compose does not pass it on.
#
# Worker measurements are approved ONCE per (network, version): the measured compose-name is stable
# (outlayer-<component>-<net>-<ver>), so re-runs / extra instances of the same version hit the
# idempotent is_measurements_approved check and skip.
#
# worker:   deploy -> read measurements -> owner-approve on the register-contract -> wait for the
#           worker to register by itself (restarted only if it gave up waiting). Owner key stays
#           on the Mac.
# keystore: deploy -> read the CVM's measurements, instance id and compose hash from its guest
#           agent -> if the DAO has not approved this build yet (its guest OS, its compose
#           hash): propose it, and continue with --resume once it is executed (--auto waits for
#           the execute and continues) -> restart the keystore so it registers -> read the key
#           and "Proposal ID: N" from the current boot of the keystore's log -> check that
#           registration N on the DAO is this CVM's (key, five measurements, instance, compose)
#           -> the members vote FOR THAT KEY (DAO_CHAIN: sent with the local keys, or printed)
#           -> poll until ready. One vote per release, one per instance.
#
# Examples:
#   ./scripts/deploy_tdx.sh worker   testnet --version 0.1.35 --node root@$DAL_HOST
#   ./scripts/deploy_tdx.sh worker   testnet worker-b --version 0.1.35 --node root@$DAL_HOST
#   ./scripts/deploy_tdx.sh worker   testnet worker-b --version 0.1.35 --node root@$DAL_HOST --resume
#   ./scripts/deploy_tdx.sh keystore testnet --version 0.1.35 --node root@$DAL_HOST
#   ./scripts/deploy_tdx.sh keystore testnet --version 0.1.35 --node root@$DAL_HOST --auto
set -euo pipefail

DEPLOY_VERSION=""; NODE=""; DIGEST=""; DRY_RUN=false; GATEWAY_URL=""; OS_IMAGE=""; KMS_URL=""; RESUME=false
AUTO=false
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
  --resume)      RESUME=true; shift;;
  --auto)        AUTO=true; shift;;
  --print)       export DAO_CHAIN=print; shift;;
  --dry-run|--info) DRY_RUN=true; shift;;
  *) POS+=("$1"); shift;;
esac; done
COMPONENT="${POS[0]:-}"; NETWORK="${POS[1]:-testnet}"; INSTANCE_NAME="${POS[2]:-}"

case "$COMPONENT" in worker|keystore) ;; *) echo "component must be worker|keystore (got '$COMPONENT')" >&2; exit 1;; esac
case "$NETWORK" in testnet|mainnet) ;; *) echo "network must be testnet|mainnet (got '$NETWORK')" >&2; exit 1;; esac
WORKER_RESUME=false
if $RESUME; then
  [ -n "$INSTANCE_NAME" ] || { echo "--resume needs the instance name of the deployed CVM" >&2; exit 1; }
  if [ "$COMPONENT" = worker ]; then
    [ -z "$OS_IMAGE" ] || { echo "worker --resume continues a deploy or an --os-image run: give it without --os-image" >&2; exit 1; }
    WORKER_RESUME=true
  fi
fi
if $AUTO; then
  [ "$NETWORK" = testnet ] || { echo "--auto is testnet only: mainnet DAO steps are voted and executed by the members on their own machines" >&2; exit 1; }
  [ "${DAO_CHAIN:-send}" = send ] || { echo "--auto waits for DAO steps it sends itself: it does not go with --print (DAO_CHAIN=$DAO_CHAIN)" >&2; exit 1; }
fi
[ -n "$DEPLOY_VERSION" ] || { echo "--version <ver> required (e.g. --version 0.1.35)" >&2; exit 1; }
[ -n "$NODE" ] || { echo "--node <ssh-target> required (e.g. --node root@<node-ip>)" >&2; exit 1; }

# The node hosts (DAL_HOST, AMS_HOST) live in the gitignored .env.nodes at the repo root.
ENV_NODES="$(cd "$(dirname "$0")/.." && pwd)/.env.nodes"
[ -f "$ENV_NODES" ] && { set -a; source "$ENV_NODES"; set +a; }
: "${DAL_HOST:?DAL_HOST unset — put it in .env.nodes at the repo root}"
: "${AMS_HOST:?AMS_HOST unset — put it in .env.nodes at the repo root}"

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
    "$DAL_HOST") echo "$pm:order" ;;
    # Haarlem — NL. Nothing known to refuse it.
    "$AMS_HOST") echo "none" ;;
    # A node nobody has measured: left alone rather than guessed at.
    *) echo "" ;;
  esac
}

# ---------------------------------------------------------------------------
# The KMS site a node belongs to, keyed like node_excludes by the HOST of `--node`.
#
# A CVM reaches only its own node's KMS, whatever name it is given: every kms-v2
# name resolves to the host there, and the certificate that answers carries only
# that node's name. With another site's URL dstack-prepare fails on the certificate
# and the guest reboots, the vmm starts it again, and so on forever. The worker
# never starts, so no heartbeat or chain transaction shows the loop. A new node
# needs its row here; a node without one is not checked.
node_kms_site() {
  case "${1#*@}" in
    "$DAL_HOST") echo "dal-01" ;;
    "$AMS_HOST") echo "ams-01" ;;
    *) echo "" ;;
  esac
}

if [ -n "$KMS_URL" ]; then
  KMS_HOST="${KMS_URL#*://}"; KMS_HOST="${KMS_HOST%%[:/]*}"
  case "$KMS_HOST" in
    kms-v2.*.dstack.outlayer.ai)
      KMS_SITE="${KMS_HOST#kms-v2.}"; KMS_SITE="${KMS_SITE%.dstack.outlayer.ai}"
      NODE_SITE="$(node_kms_site "$NODE")"
      if [ -n "$NODE_SITE" ] && [ "$KMS_SITE" != "$NODE_SITE" ]; then
        echo "--kms-url is the KMS of $KMS_SITE, but --node $NODE is $NODE_SITE: the CVM would reboot forever." >&2
        echo "Use --kms-url https://kms-v2.$NODE_SITE.dstack.outlayer.ai:11102, or the --node of $KMS_SITE." >&2
        exit 1
      fi
      ;;
  esac
fi

VER="${DEPLOY_VERSION#v}"
SUFFIX=$([ "$NETWORK" = mainnet ] && echo near || echo testnet)
OWNER="owner.outlayer.$SUFFIX"
# Builds are approved by the DAO once it carries governance: a proposal that members vote on and
# anyone executes after the delay. GOV_MEMBER proposes and votes from this machine.
GOV_DAO="dao.outlayer.$SUFFIX"
GOV_MEMBER="${GOV_MEMBER:-zavodil.$SUFFIX}"
# shellcheck source=lib/dao_gov.sh
source "$(dirname "$0")/lib/dao_gov.sh"

# drive_until_executed <dao> <member> <action-json> — dao_drive, and with --auto dao_drive again
# every AUTO_WAIT_SEC while the proposal waits (rc 2), at most AUTO_WAITS times. The testnet
# delay is 60 s and the members' keys are local, so the first retry executes it. Returns the last
# dao_drive's rc: 0 executed, 1 error, 2 still waiting (the caller prints what is left).
AUTO_WAIT_SEC=65; AUTO_WAITS=10
drive_until_executed() {
  local rc=0 n=0 open
  dao_drive "$@" || rc=$?
  while $AUTO && [ "$rc" -eq 2 ] && [ "$n" -lt "$AUTO_WAITS" ]; do
    n=$((n + 1))
    open=$(dao_find_open "$1" "$3" || true)
    case "$(echo "$open" | cut -s -d' ' -f2)" in
      Approved) echo "  --auto: waiting ${AUTO_WAIT_SEC}s for proposal #${open%% *}'s delay ($n/$AUTO_WAITS)" ;;
      Pending)  echo "  --auto: waiting ${AUTO_WAIT_SEC}s for proposal #${open%% *}'s votes ($n/$AUTO_WAITS)" ;;
      *)        echo "  --auto: waiting ${AUTO_WAIT_SEC}s for the proposal ($n/$AUTO_WAITS)" ;;
    esac
    sleep "$AUTO_WAIT_SEC"
    rc=0; dao_drive "$@" || rc=$?
  done
  return "$rc"
}
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
print(json.dumps(m, separators=(\",\", \":\")))' 2>/dev/null" 2>/dev/null \
    | grep -oE '^\{"mrtd":"[a-f0-9]{96}","rtmr0":"[a-f0-9]{96}","rtmr1":"[a-f0-9]{96}","rtmr2":"[a-f0-9]{96}","rtmr3":"[a-f0-9]{96}"\}$' | tail -1
}

# What the CVM named $NAME is, from its own guest agent over the node loopback:
# "<instance_id> <compose_hash> <app_id>". This is the operator's own reading of the CVM they
# deployed; the registration on chain is checked against it.
agent_identity() {
  node_run "p=\$(NAME=$NAME ./worker-ctl.sh port 2>/dev/null); case \"\$p\" in ''|'<'*) exit 0;; esac; \
    curl -s --max-time 5 \"http://127.0.0.1:\$p/prpc/Info?json\" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(\"IDENT\", d[\"instance_id\"], d[\"compose_hash\"], d[\"app_id\"])' 2>/dev/null" 2>/dev/null | grep -oE '^IDENT [a-f0-9]{40} [a-f0-9]{64} [a-f0-9]{40}$' | tail -1 | cut -d' ' -f2-
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

if $WORKER_RESUME; then
echo "[0-1] --resume: the CVM '$NAME' stays as deployed — no KMS check, no digest to resolve"
else
# [0] The node's KMS refuses every device but this node's: through it an approved build is
# approved for this hardware only (deploy/self-hosted-tdx/tools/check-kms-binding.sh says why).
# Read-only; a node that fails it gets no deploy.
echo "[0] KMS binding on $NODE..."
if ! node_run "./tools/check-kms-binding.sh"; then
  echo "  refused: the node's KMS is not bound to its hardware (deploy/self-hosted-tdx/kms/README.md)," >&2
  echo "  or the check is not on the node yet (deploy/self-hosted-tdx/sync-node.sh <host>)" >&2
  exit 1
fi

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
fi  # worker --resume deploys nothing

if $DRY_RUN; then
  if $AUTO; then echo "(dry-run) --auto: a DAO step that waits is driven again every ${AUTO_WAIT_SEC}s, up to $AUTO_WAITS times, and the run continues"; fi
  if $WORKER_RESUME; then
    echo "(dry-run) would: read the measurements of the running CVM '$NAME' on $NODE -> their approval on $REGISTER (the DAO proposal, when it executes, the execute command) -> once approved, the worker's registration (restarted only if it gave up waiting)"
    exit 0
  fi
  if [ -n "$OS_IMAGE" ]; then
    gate=$([ "$COMPONENT" = worker ] && echo "approve on $REGISTER (signer $OWNER) -> wait for it to register" || echo "approve on $DAO by DAO vote ($(dao_chain_mode)) -> wait for its registration -> members vote ($(dao_chain_mode)) -> poll /health")
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
    echo "(dry-run) would: deploy CVM '$NAME' on $NODE${GATEWAY_URL:+ (gateway-url=$GATEWAY_URL)} -> read measurements -> approve on $DAO by DAO vote ($(dao_chain_mode)) -> wait for its registration -> members vote ($(dao_chain_mode)) -> poll /health"
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
elif $WORKER_RESUME; then
echo "[2/5] --resume: no deploy"
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
echo "[3/5] Read TEE measurements from the CVM's guest agent$($WORKER_RESUME || echo " (waiting for boot)")..."
MEAS=""
# A resumed CVM booted long ago: it is on this node and running, or there is nothing to wait for.
if $WORKER_RESUME; then
  VMS=$(node_run "./worker-ctl.sh status" 2>/dev/null | sed 's/│/|/g' || true)
  ROW=$(printf '%s\n' "$VMS" | awk -F'|' -v want="$NAME" '{ n=$4; gsub(/[[:space:]]/, "", n); if (n == want) print }')
  if [ -z "$ROW" ]; then
    echo "  There is no CVM '$NAME' on $NODE. The $NETWORK workers there:" >&2
    printf '%s\n' "$VMS" | awk -F'|' -v net="$NETWORK-worker-" '{ n=$4; s=$5; gsub(/[[:space:]]/, "", n); gsub(/[[:space:]]/, "", s); if (index(n, net) == 1) print "    " n "  (" s ")" }' >&2
    exit 1
  fi
  printf '%s' "$ROW" | grep -q running || {
    echo "  The CVM '$NAME' on $NODE is not running: $(printf '%s' "$ROW" | awk -F'|' '{ s=$5; gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); print s }')" >&2
    echo "  On the node: NAME=$NAME ./worker-ctl.sh start" >&2
    exit 1
  }
fi
MEAS_TRIES=$($WORKER_RESUME && echo 2 || echo 20)
for i in $(seq 1 "$MEAS_TRIES"); do
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
if [ -z "$MEAS" ] && $WORKER_RESUME; then
  echo "  The CVM '$NAME' does not answer on $NODE: is it running? On the node: NAME=$NAME ./worker-ctl.sh status" >&2; exit 1
fi
[ -n "$MEAS" ] || { echo "  Could not read measurements after ~4min. Check: NAME=$NAME worker-ctl.sh follow" >&2; exit 1; }
MRTD=$(printf '%s' "$MEAS" | grep -oE '"mrtd":"[a-f0-9]{96}"' | grep -oE '[a-f0-9]{96}')
RTMR3=$(printf '%s' "$MEAS" | grep -oE '"rtmr3":"[a-f0-9]{96}"' | grep -oE '[a-f0-9]{96}')
echo "  mrtd=$MRTD"
echo "  rtmr3=$RTMR3"

# [4/5] approve measurements on the register-contract (idempotent)
echo "[4/5] Approve measurements on $REGISTER..."
APPROVED=$(near contract call-function as-read-only "$REGISTER" is_measurements_approved \
  json-args "{\"measurements\":$MEAS}" network-config "$NETWORK" now 2>/dev/null | tr -d '[:space:]' || true)
if printf '%s' "$APPROVED" | grep -qi true; then
  echo "  already approved — skipping (approve-once per net+version)"
elif dao_has_governance "$GOV_DAO"; then
  # A worker build opens keystore sessions: approving it is a DAO decision.
  echo "  through the DAO $GOV_DAO (member $GOV_MEMBER)"
  rc=0; drive_until_executed "$GOV_DAO" "$GOV_MEMBER" "$(dao_measurements_action worker "$REGISTER" "$MEAS")" || rc=$?
  if [ "$rc" -eq 2 ]; then
    echo "  Next:"
    echo "    1. Send the command above (the propose, a member's vote, or the execute once its time has come)."
    echo "    2. Run this — nothing is redeployed; run it again as often as you like:"
    echo "         $0 worker $NETWORK $NAME --version $DEPLOY_VERSION --node $NODE --resume$($AUTO && echo " --auto")"
    echo "       Before the execute it shows when the proposal executes and the command that executes it;"
    echo "       after it, it checks that the worker registered."
    echo "  The CVM '$NAME' is up and registers by itself if the proposal executes within ~50 min of its"
    echo "  first boot (it waits ~8 min per boot, and its container restarts 5 times). Later, --resume"
    echo "  restarts it."
    exit 3
  fi
  [ "$rc" -eq 0 ] || { echo "  approval through the DAO failed" >&2; exit 1; }
  # The DAO records the proposal as executed before its Call reaches the register: check there.
  sleep 3
  near contract call-function as-read-only "$REGISTER" is_measurements_approved \
    json-args "{\"measurements\":$MEAS}" network-config "$NETWORK" now 2>/dev/null | grep -q true \
    || { echo "  the DAO executed the proposal, but $REGISTER does not list the build as approved" >&2; exit 1; }
  echo "  measurements approved"
else
  near contract call-function as-transaction "$REGISTER" add_approved_measurements \
    json-args "{\"measurements\":$MEAS,\"clear_others\":false}" \
    prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$OWNER" network-config "$NETWORK" sign-with-legacy-keychain send
  echo "  measurements approved (owner; the DAO has no governance yet)"
fi

# [5/5] wait for the worker to come up. It polls is_measurements_approved every 5 s for ~8 min
# (registration.rs wait_for_measurements_approval) and registers by itself once [4/5] approved,
# so no restart is needed. Only a worker that gave up (approval later than its window: the
# process exits) is restarted, once. A worker whose key is already on the contract (an OS image
# upgrade keeps the disk, and the key on it) does not register again. Either way it is up only
# once both TEE sessions are open (coordinator, then keystore): "TEE session registered with
# keystore" is its last startup step. A stop past the registration (the startup attestation, a
# session) is not cured by a restart: its cause is shown and the run ends. Only lines from this
# run on count ($W_SINCE): the container log survives a restart, and an earlier boot's line says
# nothing about this one (--resume reads the earlier boots first, below).
W_UP="TEE session registered with keystore"
W_FATAL="Failed to send startup attestation|Failed to register TEE session|Exceeded the prepaid gas|did not verify|No cached collateral"
worker_fatal() { # <log lines> → the cause of the stop and what to do; exits 1
  local cause
  cause=$(printf '%s\n' "$1" | grep -E "$W_FATAL|failed: |❌" | tail -2 || true)
  echo "  The worker stopped, and a restart does not cure it:" >&2
  printf '%s\n' "${cause:-  (its log names no cause; on the node: NAME=$NAME ./worker-ctl.sh logs)}" | sed 's/^/    /' >&2
  if printf '%s' "$cause" | grep -q "Signature verification failed"; then
    echo "  The server refuses the session this worker signs: it is older than the worker. Deploy it" >&2
    echo "  (the coordinator, or the keystore if the line names it), then restart this worker." >&2
  fi
  echo "  Once fixed, on $NODE: NAME=$NAME ./worker-ctl.sh restart — then run this --resume again." >&2
  exit 1
}
worker_watch() { # rounds of 12 s → 0 up, 1 a stop a restart does not cure (exits), 2 undecided
  local i L
  for i in $(seq 1 "$1"); do
    L=$(node_run "NAME=$NAME TAIL=400 ./worker-ctl.sh logs" 2>/dev/null \
      | awk -v t="$W_SINCE" '/^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ && substr($0, 1, 19) >= t' || true)
    if printf '%s' "$L" | grep -qF "$W_UP"; then
      echo "  UP:"; printf '%s' "$L" | grep -E "registered successfully|Key registered and ready|TEE session registered" | tail -3
      return 0
    fi
    printf '%s' "$L" | grep -qE "$W_FATAL" && worker_fatal "$L"
    sleep 12
  done
  return 2
}
FIRST_WATCH=45
STAGE="[5/5] Wait for the worker to come up (it registers by itself once the measurements are approved)..."
if $WORKER_RESUME; then
  # Where the worker stands, from the last of its own lines that says so (the container log keeps
  # every boot): up; in a boot that is starting (it logs "registration enabled", then checks the
  # approval every 5 s, registers, opens its sessions); or stopped. A stop is final only once its
  # container has used its restarts (compose: on-failure:5, each within seconds), so a stop is
  # read twice: restarting the CVM under a boot that is sending its registration would orphan
  # that key. A restart cures one stop only, the approval that came after the worker gave up
  # waiting; any other stop is the operator's to fix, and its cause is shown.
  WLOG=""; LAST=""
  worker_read() {
    WLOG=$(node_run "NAME=$NAME TAIL=400 ./worker-ctl.sh logs" 2>/dev/null || true)
    LAST=$(printf '%s\n' "$WLOG" \
      | grep -E "$W_UP|$W_FATAL|Worker stopped|Worker registration enabled|Measurements not yet approved|registered successfully|Key registered and ready|Registering TEE session" \
      | tail -1 || true)
  }
  is_stop() { printf '%s' "$1" | grep -qE "$W_FATAL|Worker stopped"; }
  worker_read
  if is_stop "$LAST"; then sleep 15; worker_read; fi
  if printf '%s' "$LAST" | grep -qF "$W_UP"; then
    echo "[5/5] The worker is up:"
    echo "  $LAST"
    echo "Done. Manage: ssh $NODE -> su - $REMOTE_USER -> cd $REMOTE_DIR -> NAME=$NAME ./worker-ctl.sh follow"
    exit 0
  elif is_stop "$LAST"; then
    if printf '%s\n' "$WLOG" | grep -E "Measurements not approved after|$W_FATAL" | tail -1 | grep -q "Measurements not approved after"; then
      FIRST_WATCH=0
      STAGE="[5/5] The worker gave up waiting for the approval before it came, and its container is not restarting."
    else
      echo "[5/5]" >&2
      worker_fatal "$WLOG"
    fi
  elif [ -n "$LAST" ]; then
    FIRST_WATCH=10
    STAGE="[5/5] The worker is in a boot that is starting; it sees the approval within seconds..."
  fi
fi
echo "$STAGE"
if worker_watch "$FIRST_WATCH"; then
  echo "Done. Manage: ssh $NODE -> su - $REMOTE_USER -> cd $REMOTE_DIR -> NAME=$NAME ./worker-ctl.sh follow"
  exit 0
fi
if [ "$FIRST_WATCH" -gt 0 ]; then
  echo "  not up within ~$((FIRST_WATCH * 12 / 60 + 1)) min: restarting it once (soft)..."
else
  echo "  restarting it (soft)..."
fi
node_run "NAME=$NAME ./worker-ctl.sh restart" >/dev/null || true
if worker_watch 20; then
  echo "Done. Manage: ssh $NODE -> su - $REMOTE_USER -> cd $REMOTE_DIR -> NAME=$NAME ./worker-ctl.sh follow"
  exit 0
fi
echo "  No decisive result yet — check: NAME=$NAME worker-ctl.sh follow (on the node)"
exit 0
fi  # end worker

# ============================== keystore flow ==============================
# The DAO approves a keystore's build once (its guest OS and its compose hash, the same for
# every instance of a release) and the members vote for every instance, naming its key. The
# keystore submits its own registration on boot, once its build is approved (it logs
# "Proposal ID: N"). Everything is signed LOCALLY (keys stay on the Mac).

# Logs come from the dstack-keystore-1 container (worker-ctl.sh defaults to dstack-worker-1).
ks_logs() { node_run "NAME=$NAME CONTAINER=$KS_CONTAINER TAIL=${1:-600} ./worker-ctl.sh logs"; }

# The keystore's own log lines: its timestamp, level and module, then the message. Each pattern
# below is one exact message of keystore-worker (main.rs, tee_registration.rs), anchored at both
# ends, so a line ending in text a request put there does not match.
KS_LINE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z +(INFO|WARN|ERROR) keystore_worker(::[a-z_]+)*: '
KS_START="${KS_LINE}Starting NEAR OutLayer Keystore Worker\$"
KS_KEY="${KS_LINE}📂 Using keystore public key: [a-z0-9-]+:[A-Za-z0-9]+\$"
KS_PROPOSAL="${KS_LINE}(📤 Registration submitted! |✅ Registration submitted successfully! )Proposal ID: [0-9]+\$"
KS_UNAPPROVED="${KS_LINE}⏸️  Registration NOT submitted — this build is not approved by the DAO yet\$"
KS_READY="${KS_LINE}✅ TEE registration complete! Keystore is now ready to serve requests\$"

# The key the keystore's current boot printed (a new one every boot), or nothing yet.
ks_live_key() { ks_boot_logs 2>/dev/null | grep -E "$KS_KEY" | tail -1 | sed 's/.*: //' || true; }

# The keystore's log of its CURRENT boot: everything after its last start line. A keystore opens
# its port only once it is registered, so until then this part of the log holds nothing a
# request could have put there; lines of earlier boots — when the instance served — are left out.
ks_boot_logs() {
  ks_logs "${1:-20000}" 2>/dev/null | awk -v start="$KS_START" '
    $0 ~ start { n = 0 } { buf[n++] = $0 } END { for (i = 0; i < n; i++) print buf[i] }'
}

# Whether the keystore answers on its port (loopback on the node): it is registered and serving.
ks_serving() {
  local h
  h=$(node_run "set -e; u=\$(NAME=$NAME ./worker-ctl.sh uuid); \
    p=\$(for pid in \$(pgrep -f qemu-system-x86_64); do c=\$(tr '\\0' ' ' < /proc/\$pid/cmdline 2>/dev/null) || continue; \
      [[ \"\$c\" == *\"\$u\"* ]] || continue; echo \"\$c\" | grep -oE '127\\.0\\.0\\.1:[0-9]+-:8081' | sed -E 's/.*:([0-9]+)-:8081/\\1/' | head -1; break; done); \
    [ -n \"\$p\" ] && curl -fs --max-time 5 \"http://127.0.0.1:\$p/health\" || true" 2>/dev/null || true)
  [ -n "$h" ]
}

# wait_registration <tries> [<old-key>] — where this boot of the keystore stands. With <old-key>
# (the key of the boot before a restart), only a boot that printed another key counts: the key is
# minted per boot, so this holds whether or not the container log survives the restart.
# Sets KS_STATE:
#   registered        PROPOSAL_ID is its registration: the id its log printed, Pending on chain
#                     and for LIVE_KEY, the key the same boot printed
#   build_unapproved  it did not submit: the DAO has not approved its guest OS or its compose
#   ""                none of these within <tries> (12 s each)
wait_registration() {
  local tries="$1" old_key="${2:-}" i L P P_KEY P_STATUS
  PROPOSAL_ID=""; LIVE_KEY=""; KS_STATE=""
  for i in $(seq 1 "$tries"); do
    L=$(ks_boot_logs || true)
    LIVE_KEY=$(printf '%s\n' "$L" | grep -E "$KS_KEY" | tail -1 | sed 's/.*: //' || true)
    if [ -z "$LIVE_KEY" ] || { [ -n "$old_key" ] && [ "$LIVE_KEY" = "$old_key" ]; }; then
      LIVE_KEY=""; sleep 12; continue
    fi
    PROPOSAL_ID=$(printf '%s\n' "$L" | grep -E "$KS_PROPOSAL" | tail -1 | grep -oE '[0-9]+$' || true)
    if [ -n "$PROPOSAL_ID" ]; then
      P=$(near contract call-function as-read-only "$DAO" get_proposal json-args "{\"proposal_id\":$PROPOSAL_ID}" \
        network-config "$NETWORK" now 2>/dev/null || true)
      P_KEY=$(printf '%s' "$P" | grep -oE '"public_key": "[^"]+"' | head -1 | sed -E 's/.*: "([^"]+)"/\1/')
      P_STATUS=$(printf '%s' "$P" | grep -oE '"status": "[A-Za-z]+"' | head -1 | sed -E 's/.*: "([^"]+)"/\1/')
      if [ -n "$LIVE_KEY" ] && [ "$P_KEY" = "$LIVE_KEY" ] && [ "$P_STATUS" = Pending ]; then
        KS_STATE=registered; return 0
      fi
      echo "  #$PROPOSAL_ID is not the live key's pending proposal yet (key ${P_KEY:-?}, live ${LIVE_KEY:-not logged yet}, status ${P_STATUS:-?}); waiting"
      PROPOSAL_ID=""
    fi
    if printf '%s\n' "$L" | grep -qE "$KS_UNAPPROVED"; then KS_STATE=build_unapproved; return 0; fi
    sleep 12
  done
}

# Propose (or move on) one DAO approval; stops the run when it waits for votes or for the delay
# (with --auto: once drive_until_executed has waited AUTO_WAITS times).
approve_through_dao() {
  local what="$1" action="$2" rc=0
  echo "  $what: through the DAO (member $GOV_MEMBER)"
  drive_until_executed "$DAO" "$GOV_MEMBER" "$action" || rc=$?
  if [ "$rc" -eq 2 ]; then
    echo "  The CVM '$NAME' stays up and registers once this is executed. Then continue WITHOUT a"
    echo "  new deploy (a new CVM is a new instance):"
    echo "    $0 keystore $NETWORK $NAME --version $DEPLOY_VERSION --node $NODE --resume$($AUTO && echo " --auto")"
    exit 3
  fi
  [ "$rc" -eq 0 ] || { echo "  approval through the DAO failed" >&2; exit 1; }
}

# [2/6] deploy the CVM on the node (node-side deploy_tdx.sh derives the stable COMPOSE_NAME).
# GATEWAY_URL (optional) flows Mac --gateway-url -> node env -> 40-deploy-keystore.sh: when set, the
# keystore deploys gateway-enabled and gets a public HTTPS endpoint.
if [ -n "$OS_IMAGE" ]; then
# [2/6] upgrade: the existing keystore boots the new guest OS; app-id, URL, disk, env and the
# gateway registration are untouched. It is not ready from the stop until the vote lands.
echo "[2/6] Move CVM '$NAME' to $OS_IMAGE on the node (soft stop, resize --image, start)..."
OLD_KEY=$(ks_live_key)
node_run "./worker-ctl.sh set-image $NAME $OS_IMAGE"
KEYSTORE_URL=""   # unchanged by an image upgrade; nothing new to announce
elif $RESUME; then
echo "[2/6] --resume: CVM '$NAME' stays as deployed (no new deploy, so its measurements stay the approved ones)"
KEYSTORE_URL=""
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

# [4/6] The build is approved by the DAO, once, before any instance of it registers: its guest
# OS (MRTD, RTMR0-2) and the hash of its compose. Both are the same for every instance of a
# release, so the second instance finds them approved. The keystore asks the DAO itself and
# submits its registration only then.
echo "[4/6] Wait for the keystore's registration, or for what it says is not approved..."
wait_registration 20 "${OLD_KEY:-}"
RESTART=false
case "$KS_STATE" in
  registered) echo "  the build is approved: the keystore registered on its own" ;;
  build_unapproved)
    IDENT=$(agent_identity || true)
    [ -n "$IDENT" ] || { echo "  could not read the CVM's compose hash from its guest agent" >&2; exit 1; }
    COMPOSE_HASH=$(echo "$IDENT" | cut -d' ' -f2)
    OS_TUPLE=$(printf '%s' "$MEAS" | python3 -I -c 'import json,sys
m=json.load(sys.stdin); print(json.dumps({k: m[k] for k in ("mrtd","rtmr0","rtmr1","rtmr2")}, separators=(",",":")))')
    OS_OK=$(near contract call-function as-read-only "$DAO" get_approved_os_images json-args '{}' network-config "$NETWORK" now 2>/dev/null \
      | python3 -I -c 'import json,sys; print("true" if json.loads(sys.argv[1]) in json.load(sys.stdin) else "false")' "$OS_TUPLE" || echo false)
    C_OK=$(near contract call-function as-read-only "$DAO" get_approved_composes json-args '{}' network-config "$NETWORK" now 2>/dev/null \
      | python3 -I -c 'import json,sys; print("true" if sys.argv[1] in json.load(sys.stdin) else "false")' "$COMPOSE_HASH" || echo false)
    echo "  guest OS  mrtd=${MRTD:0:16}…  approved: $OS_OK"
    echo "  compose   $COMPOSE_HASH  approved: $C_OK"
    [ "$OS_OK" = true ] || approve_through_dao "guest OS" "{\"ApproveOsImage\":{\"image\":$OS_TUPLE}}"
    [ "$C_OK" = true ] || approve_through_dao "compose of v$VER" "{\"ApproveCompose\":{\"compose_hash\":\"$COMPOSE_HASH\"}}"
    RESTART=true ;;
  *) echo "  No registration and no refusal in the keystore's log after ~4min. Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow" >&2; exit 1 ;;
esac

# [5/6] A keystore that found its build unapproved stopped without submitting: restart it (the
# same CVM, the same instance) so it registers. Its key is minted per boot, and only the current
# boot's lines are read, so the registration found is the one of the key it holds now.
if $RESTART; then
  echo "[5/6] Restart the keystore so it registers against the approved build..."
  OLD_KEY=$(ks_live_key)
  node_run "NAME=$NAME ./worker-ctl.sh restart" >/dev/null || true
  wait_registration 25 "$OLD_KEY"
  [ "$KS_STATE" = registered ] || { echo "  No registration after the restart (${KS_STATE:-nothing in the log}). Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow" >&2; exit 1; }
fi

# The registration on chain must be THIS CVM's before anyone is asked to vote for it:
#   * the key is the one this boot's log printed (wait_registration);
#   * the keystore is not serving yet — a registered keystore has nothing to vote on, and a log
#     of one that serves is no longer only its own words;
#   * all five measurements are the ones its guest agent reports;
#   * the instance id, the compose hash and the app id are the guest agent's too.
if ks_serving; then
  echo "  REFUSING: the keystore in '$NAME' already serves — it is registered; there is nothing to vote on." >&2
  exit 1
fi
P_JSON=$(near contract call-function as-read-only "$DAO" get_proposal json-args "{\"proposal_id\":$PROPOSAL_ID}" network-config "$NETWORK" now 2>/dev/null || true)
SAME_MEAS=$(printf '%s' "$P_JSON" | python3 -I -c 'import json,sys
print("true" if json.load(sys.stdin)["measurements"] == json.loads(sys.argv[1]) else "false")' "$MEAS" 2>/dev/null || echo false)
if [ "$SAME_MEAS" != true ]; then
  echo "  REFUSING: registration #$PROPOSAL_ID on $DAO does not carry this CVM's measurements ($MEAS)." >&2
  exit 1
fi
FACTS=$(near contract call-function as-read-only "$DAO" get_registration_facts json-args "{\"proposal_id\":$PROPOSAL_ID}" \
  network-config "$NETWORK" now 2>/dev/null | python3 -I -c 'import json,sys
f=json.load(sys.stdin)
print(f["instance_id"], f["compose_hash"], f["app_id"]) if f else None' 2>/dev/null || true)
[ -n "$FACTS" ] && [ "$FACTS" != None ] || { echo "  registration #$PROPOSAL_ID states no build on $DAO" >&2; exit 1; }
IDENT=$(agent_identity || true)
[ -n "$IDENT" ] || { echo "  could not read the CVM's instance id from its guest agent" >&2; exit 1; }
if [ "$FACTS" != "$IDENT" ]; then
  echo "  REFUSING: registration #$PROPOSAL_ID on $DAO is not this CVM's." >&2
  echo "    this CVM (guest agent):  instance/compose/app = $IDENT" >&2
  echo "    registration on chain:   instance/compose/app = $FACTS" >&2
  exit 1
fi
echo "  registration #$PROPOSAL_ID is this CVM's:"
echo "    key          $LIVE_KEY"
echo "    instance_id  ${IDENT%% *}"
echo "    compose_hash $(echo "$IDENT" | cut -d' ' -f2)"
echo "  proposal id: $PROPOSAL_ID (live key $LIVE_KEY, pending on $DAO)"

# Vote (DAO_CHAIN, scripts/lib/dao_gov.sh). Every vote names LIVE_KEY, the key this CVM's own
# log printed: the DAO refuses it on a registration for any other key, so a vote asked for here
# cannot land on someone else's keystore. `send` votes with every member whose key is local
# until the registration executes; `print` (and mainnet always) prints one ready command per
# member. The keystore waits for the quorum up to 24 h (tee_registration.rs wait_for_approval).
if [ "$(dao_chain_mode)" = print ]; then
  echo "  Nothing sent (print mode). The members vote on the keystore's registration:"
  dao_print_votes "$DAO" "$PROPOSAL_ID" "$LIVE_KEY" || true
  echo "  Once the quorum votes, the keystore pulls its MPC-CKD master and becomes ready."
  echo "  Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow (on the node)"
  if [ -n "$KEYSTORE_URL" ]; then
    echo "  Public endpoint once READY (via dstack-gateway): $KEYSTORE_URL"
    echo "  Then: ./scripts/keystore_urls.sh $NETWORK --apply"
  fi
  exit 0
fi
dao_vote_local "$DAO" "$PROPOSAL_ID" "$LIVE_KEY"
P_STATUS=$(dao_status "$DAO" "$PROPOSAL_ID")
if [ "$P_STATUS" = Pending ]; then
  echo "  #$PROPOSAL_ID still needs votes the local keys cannot give; the keystore waits up to 24 h."
  dao_print_votes "$DAO" "$PROPOSAL_ID" "$LIVE_KEY" || true
  echo "  Then it pulls its master and becomes ready. Check: NAME=$NAME CONTAINER=$KS_CONTAINER worker-ctl.sh follow (on the node)"
  exit 0
fi
echo "  registration #$PROPOSAL_ID: $P_STATUS"

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
  L=$(ks_boot_logs || true)
  if printf '%s\n' "$L" | grep -qE "$KS_READY"; then
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
