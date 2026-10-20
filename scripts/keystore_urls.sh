#!/usr/bin/env bash
#
# Mac-side: set KEYSTORE_BASE_URLS for a network everywhere it is read, from the keystores that
# are actually live — no copying URLs by hand, no node console.
#
#   ./scripts/keystore_urls.sh <testnet|mainnet>                       # dry run: what it found, old → new per file
#   ./scripts/keystore_urls.sh <testnet|mainnet> --apply               # write the files
#   ./scripts/keystore_urls.sh <testnet|mainnet> --apply --up          # … and recreate the coordinator with them
#   … --version 0.1.94    only the keystores of this version (default: the newest version running)
#   … --all               every live keystore of the network, any version
#
# Where the list comes from: each node's running `<net>-keystore-<NNNN>-<i>` CVMs (lsvm), their
# app-id and the node's gateway domain give https://<app-id>-8081.<domain>; a URL is kept only
# when its /health answers 200 — the keystore opens its port once it is READY. The nodes are the
# source of truth: a URL saved at deploy time goes stale when a keystore is removed or never
# becomes ready, this cannot.
#
# Where it writes (each file only when its value changes; a .bak-<stamp> next to each node file):
#   worker/.env.<net>-worker-tdx    on every node that has one, and the Mac copy in
#                                   deploy/self-hosted-tdx/worker/ (never synced to a node; kept
#                                   in step because a new node's env starts from it)
#   /opt/outlayer-<net>-api/coordinator.env   on the node that runs the network's API
# When it takes effect:
#   workers      at their next deploy (scripts/deploy_tdx.sh worker …): the env is sealed into the
#                CVM at deploy time, a running worker keeps the list it booted with
#   coordinator  after `outlayer-<net>-api up` on its node (`restart` keeps the old env);
#                --up runs it
#
# No secret is printed: only the KEYSTORE_BASE_URLS line of each env file is read back, and the
# keystore URLs are public endpoints.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$HERE/../deploy/self-hosted-tdx"

# The nodes and their gateway domains (40-deploy-gateway.sh SRV_DOMAIN of each node).
NODES=(
  "dal 173.237.9.76 dstack.outlayer.ai"
  "ams 23.109.254.164 ams-01.dstack.outlayer.ai"
)

NETWORK=""; APPLY=false; UP=false; WANT_VERSION=""; ALL=false
while [[ $# -gt 0 ]]; do case "$1" in
  testnet|mainnet) NETWORK="$1"; shift ;;
  --apply) APPLY=true; shift ;;
  --up) UP=true; shift ;;
  --version) WANT_VERSION="${2:?--version needs a value, e.g. 0.1.94}"; shift 2 ;;
  --all) ALL=true; shift ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac; done
[ -n "$NETWORK" ] || { echo "usage: $0 <testnet|mainnet> [--version 0.1.N | --all] [--apply [--up]]" >&2; exit 2; }
$UP && ! $APPLY && { echo "--up needs --apply" >&2; exit 2; }
# 0.1.94 → 0194, the digits deploy_tdx.sh's instance names carry (testnet-keystore-0194-1)
if [ -n "$WANT_VERSION" ]; then
  [[ "$WANT_VERSION" =~ ^v?0\.([0-9]+)\.([0-9]+)$ ]] || { echo "--version must look like 0.1.94" >&2; exit 2; }
  WANT_TAG=$(printf '0%d%02d' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}")
fi

node_sh() { ssh -o BatchMode=yes -o ConnectTimeout=10 "root@$1" "$2" 2>/dev/null; }

# The version tag of a keystore CVM name, in both namings deploy_tdx.sh produces:
#   testnet-keystore-0194-1                (an instance name given on the command line)
#   outlayer-keystore-testnet-0.1.94-1     (its default)
# → 0194. Empty for any other name.
name_tag() {
  if [[ "$1" =~ ^$NETWORK-keystore-([0-9]+)-[0-9]+$ ]]; then echo "${BASH_REMATCH[1]}"
  elif [[ "$1" =~ ^outlayer-keystore-$NETWORK-0\.([0-9]+)\.([0-9]+)-[0-9]+$ ]]; then printf '0%d%02d\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  fi
}

echo "== $NETWORK keystores on the nodes =="
ROWS=()   # "tag site url status"
for n in "${NODES[@]}"; do
  read -r site host domain <<<"$n"
  out=$(node_sh "$host" "su - outlayer -c 'python3 /home/outlayer/meta-dstack/dstack/vmm/src/vmm-cli.py --url http://127.0.0.1:11000 lsvm'" || true)
  [ -n "$out" ] || { echo "  !! $site ($host): no answer from its vmm — not counted" >&2; continue; }
  while IFS='|' read -r name appid status; do
    tag=$(name_tag "$name")
    url="https://$appid-8081.$domain"
    if [ "$status" = running ]; then
      code=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}' "$url/health" || true)
    else
      code="-"
    fi
    echo "  $site  $name  ${appid:0:8}…  $status  /health $code${tag:+  (tag $tag)}"
    [ -n "$tag" ] || echo "  !! $name: its name carries no version this script reads — counted only with --all" >&2
    [ "$status" = running ] && [ "$code" = 200 ] && ROWS+=("${tag:-?} $site $url")
  done < <(printf '%s\n' "$out" | sed 's/│/|/g' | awk -F'|' -v net="$NETWORK" '
    { name=$4; appid=$3; status=$5; gsub(/[[:space:]]/,"",name); gsub(/[[:space:]]/,"",appid); gsub(/[[:space:]]/,"",status)
      if (appid ~ /^[0-9a-f]{40}$/ && (index(name, net "-keystore-") == 1 || index(name, "outlayer-keystore-" net "-") == 1))
        print name "|" appid "|" status }')
done
[ "${#ROWS[@]}" -gt 0 ] || { echo "no live $NETWORK keystore answers /health 200 — nothing to set" >&2; exit 1; }

if $ALL; then
  PICK=("${ROWS[@]}"); echo "  using: every live keystore (--all)"
else
  [ -n "${WANT_VERSION:-}" ] || WANT_TAG=$(printf '%s\n' "${ROWS[@]}" | awk '$1 != "?" {print $1}' | sort -n | tail -1)
  [ -n "$WANT_TAG" ] || { echo "no live $NETWORK keystore has a version in its name — use --all or --version" >&2; exit 1; }
  PICK=(); for r in "${ROWS[@]}"; do [ "${r%% *}" = "$WANT_TAG" ] && PICK+=("$r"); done
  [ "${#PICK[@]}" -gt 0 ] || { echo "no live $NETWORK keystore of version tag $WANT_TAG" >&2; exit 1; }
  if [ -n "$WANT_VERSION" ]; then echo "  using: version $WANT_VERSION (tag $WANT_TAG), as asked"
  else echo "  using: tag $WANT_TAG, the newest version running (--version 0.1.N picks another, --all takes every one)"; fi
  for n in "${NODES[@]}"; do
    read -r site _ _ <<<"$n"
    printf '%s\n' "${PICK[@]}" | awk '{print $2}' | grep -qx "$site" \
      || echo "  !! $site has no live keystore of tag $WANT_TAG: the list will not include it" >&2
  done
fi
# one URL per (site, app-id), in node order
NEW=$(printf '%s\n' "${PICK[@]}" | awk '{print $3}' | awk '!seen[$0]++' | paste -sd, -)
echo "  KEYSTORE_BASE_URLS=$NEW"
echo

stamp=$(date -u +%Y%m%d-%H%M%S)
NEW_B64=$(printf '%s' "$NEW" | base64 | tr -d '\n')
# Replace (or append) the KEYSTORE_BASE_URLS line of $1, keeping the file's owner and mode
# (written in place, not replaced). Prints OLD:<value> and, with apply, DONE.
SETTER='import base64, os, sys
path, new, apply, stamp = sys.argv[1], base64.b64decode(sys.argv[2]).decode(), sys.argv[3] == "1", sys.argv[4]
lines = open(path).read().splitlines(keepends=True)
old = [l.split("=", 1)[1].strip() for l in lines if l.startswith("KEYSTORE_BASE_URLS=")]
print("OLD:" + (old[-1] if old else "<unset>"))
if apply and (not old or old[-1] != new):
    if stamp:
        with open(path + ".bak-" + stamp, "w") as b: b.writelines(lines)
        os.chmod(path + ".bak-" + stamp, 0o600)
    out = [l for l in lines if not l.startswith("KEYSTORE_BASE_URLS=")]
    if out and not out[-1].endswith("\n"): out[-1] += "\n"
    out.append("KEYSTORE_BASE_URLS=" + new + "\n")
    with open(path, "r+") as f: f.seek(0); f.writelines(out); f.truncate()
    print("DONE")'
show() { # label old
  if [ "$2" = "$NEW" ]; then echo "  $1: already set"
  else echo "  $1:"; echo "      was: $2"; echo "      now: $NEW$($APPLY || echo '   (dry run)')"; fi
}

echo "== files =="
CHANGED_API=""
for n in "${NODES[@]}"; do
  read -r site host _ <<<"$n"
  for f in "/home/outlayer/self-hosted-tdx/worker/.env.$NETWORK-worker-tdx" "/opt/outlayer-$NETWORK-api/coordinator.env"; do
    res=$(node_sh "$host" "[ -f '$f' ] || exit 0; python3 -c '$SETTER' '$f' '$NEW_B64' '$($APPLY && echo 1 || echo 0)' '$stamp'" || true)
    [ -n "$res" ] || continue
    old=$(printf '%s\n' "$res" | sed -n 's/^OLD://p')
    show "$site $f" "$old"
    if printf '%s' "$res" | grep -qx DONE && [[ "$f" == */coordinator.env ]]; then CHANGED_API="$site $host"; fi
  done
done
mac="$TREE/worker/.env.$NETWORK-worker-tdx"
if [ -f "$mac" ]; then
  res=$(python3 -c "$SETTER" "$mac" "$NEW_B64" "$($APPLY && echo 1 || echo 0)" "")
  show "mac  deploy/self-hosted-tdx/worker/.env.$NETWORK-worker-tdx" "$(printf '%s\n' "$res" | sed -n 's/^OLD://p')"
fi
echo

$APPLY || { echo "DRY RUN: nothing written. Re-run with --apply (and --up to recreate the $NETWORK coordinator)."; exit 0; }
echo "Workers pick the list up at their next deploy: ./scripts/deploy_tdx.sh worker $NETWORK … --node root@<host>"
if [ -n "$CHANGED_API" ]; then
  read -r site host <<<"$CHANGED_API"
  if $UP; then
    echo "Recreating the $NETWORK coordinator on $site so it reads the new list (outlayer-$NETWORK-api up)..."
    node_sh "$host" "outlayer-$NETWORK-api up" | tail -5
  else
    echo "The $NETWORK coordinator reads it after: ssh root@$host outlayer-$NETWORK-api up   (or re-run with --up)"
  fi
fi
