#!/usr/bin/env bash
# Upgrade a contract through the DAO: store the wasm as a blob (if it is not stored yet), propose
# the upgrade (or find the open proposal), vote, and execute once it is approved and its delay has
# passed. Run it again later to move the same proposal on — it never proposes twice.
#
#   scripts/dao_upgrade.sh --network testnet --target main --wasm contract/res/outlayer_contract.wasm
#   scripts/dao_upgrade.sh --network mainnet --target dao --wasm <file> --member zavodil.near --migrate
#
#   --target   main | dao | worker   (outlayer.<net>, dao.outlayer.<net>, worker.outlayer.<net>)
#   --migrate  call the new code's migrate() in the same batch (a release that changes the state)
#   --member   the DAO member who proposes and votes (default zavodil.<net>)
#   --storer   the DAO member who stores the blob and pays its deposit, refunded when the upgrade
#              executes (default --member)
#   --root     another set of accounts: <root>, dao.<root>, worker.<root> (e.g. testoutlayerdao.testnet)
#
# The blob's sha256 is the code hash the account reports after the deploy. Before voting, build the
# release reproducibly and compare: a hash nobody can rebuild is a reason to vote against.

set -euo pipefail
cd "$(dirname "$0")/.."

NETWORK=""; TARGET=""; WASM=""; MIGRATE=false; MEMBER=""; STORER=""; ROOT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?}"; shift 2 ;;
        --target)  TARGET="${2:?}"; shift 2 ;;
        --wasm)    WASM="${2:?}"; shift 2 ;;
        --migrate) MIGRATE=true; shift ;;
        --member)  MEMBER="${2:?}"; shift 2 ;;
        --storer)  STORER="${2:?}"; shift 2 ;;
        --root)    ROOT="${2:?}"; shift 2 ;;
        *) echo "unknown argument: $1"; exit 1 ;;
    esac
done
case "$NETWORK" in testnet|mainnet) ;; *) echo "--network testnet|mainnet"; exit 1 ;; esac
[ -f "$WASM" ] || { echo "--wasm <file> (built wasm)"; exit 1; }
SUFFIX=$([ "$NETWORK" = mainnet ] && echo near || echo testnet)
ROOT="${ROOT:-outlayer.$SUFFIX}"
DAO="dao.$ROOT"
case "$TARGET" in
    main) TARGET_ACC="$ROOT" ;;
    dao) TARGET_ACC="$DAO" ;;
    worker) TARGET_ACC="worker.$ROOT" ;;
    *) echo "--target main|dao|worker"; exit 1 ;;
esac
MEMBER="${MEMBER:-zavodil.$SUFFIX}"
STORER="${STORER:-$MEMBER}"
export NETWORK
# shellcheck source=lib/dao_gov.sh
source scripts/lib/dao_gov.sh

dao_has_governance "$DAO" || { echo "$DAO has no governance yet: upgrade it with its full-access key"; exit 1; }

HASH=$(python3 -I -c '
import hashlib,sys
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
b=hashlib.sha256(open(sys.argv[1],"rb").read()).digest(); n=int.from_bytes(b,"big"); o=""
while n: n,r=divmod(n,58); o=A[r]+o
print("1"*(len(b)-len(b.lstrip(b"\0")))+o)' "$WASM")
SIZE=$(wc -c < "$WASM" | tr -d ' ')
echo "Upgrade $TARGET_ACC to $HASH ($SIZE bytes, migrate=$MIGRATE) through $DAO on $NETWORK"

if near contract call-function as-read-only "$DAO" get_blob json-args "{\"hash\":\"$HASH\"}" \
    network-config "$NETWORK" now 2>/dev/null | grep -q '"storer"'; then
    echo "  blob already stored"
else
    DEPOSIT=$(python3 -I -c 'import sys; print(f"{int(sys.argv[1])*1e19*1.1/1e24:.4f} NEAR")' "$SIZE")
    echo "  storing the blob as $STORER (deposit $DEPOSIT, refunded when the upgrade executes)"
    OUT=$(near contract call-function as-transaction "$DAO" store_blob file-args "$WASM" \
        prepaid-gas '100 Tgas' attached-deposit "$DEPOSIT" sign-as "$STORER" \
        network-config "$NETWORK" sign-with-legacy-keychain send 2>&1) \
        || { echo "  store_blob failed:"; printf '%s\n' "$OUT" | grep -iE 'panicked|error|balance|not enough' | head -3; exit 1; }
fi

ACTION="{\"Upgrade\":{\"target\":\"$TARGET_ACC\",\"code_hash\":\"$HASH\",\"migrate\":$MIGRATE}}"
rc=0; dao_drive "$DAO" "$MEMBER" "$ACTION" || rc=$?
[ "$rc" -eq 2 ] && exit 0
[ "$rc" -eq 0 ] || exit 1

HEX=$(python3 -I -c '
import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$WASM")
DEPLOYED=$(near account view-account-summary "$TARGET_ACC" network-config "$NETWORK" now 2>/dev/null \
    | grep -oiE 'checksum hex\)[[:space:]]+[0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' || true)
if [ "$DEPLOYED" = "$HEX" ]; then
    echo "  $TARGET_ACC runs $HASH"
else
    echo "  $TARGET_ACC runs sha256 ${DEPLOYED:-?}, expected $HEX" >&2
    exit 1
fi
