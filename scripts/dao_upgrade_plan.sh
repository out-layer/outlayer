#!/usr/bin/env bash
# Print the transactions of a DAO upgrade, with every value filled in; send nothing.
#
#   scripts/dao_upgrade_plan.sh --network testnet --target main --wasm contract/target/near/outlayer_contract.wasm \
#       --root tod3.outlayer-alice.testnet --member outlayer-alice.testnet --member outlayer-bob.testnet
#
#   --target   main | dao | worker   (<root>, dao.<root>, worker.<root>)
#   --root     the account set (default outlayer.<net>)
#   --member   a DAO member who votes; repeat it once per vote. The first one stores the blob,
#              proposes and executes. Default: zavodil.<net>
#   --migrate  the upgrade calls the new code's migrate() (a release that changes the state)
#
# The output is plain near-cli commands, one per transaction, ready to paste into any shell.
# The proposal id is known only after `propose`: the commands after it carry <ID>.
# scripts/dao_upgrade.sh sends the same transactions itself.
set -euo pipefail

NETWORK=testnet TARGET="" WASM="" ROOT="" MIGRATE=false MEMBERS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?}"; shift 2 ;;
        --target)  TARGET="${2:?}"; shift 2 ;;
        --wasm)    WASM="${2:?}"; shift 2 ;;
        --root)    ROOT="${2:?}"; shift 2 ;;
        --member)  MEMBERS+=("${2:?}"); shift 2 ;;
        --migrate) MIGRATE=true; shift ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
case "$NETWORK" in testnet|mainnet) ;; *) echo "--network testnet|mainnet" >&2; exit 1 ;; esac
[ -f "$WASM" ] || { echo "--wasm <file> (built wasm)" >&2; exit 1; }
SUFFIX=$([ "$NETWORK" = mainnet ] && echo near || echo testnet)
ROOT="${ROOT:-outlayer.$SUFFIX}"
DAO="dao.$ROOT"
case "$TARGET" in
    main) TARGET_ACC="$ROOT" ;;
    dao) TARGET_ACC="$DAO" ;;
    worker) TARGET_ACC="worker.$ROOT" ;;
    *) echo "--target main|dao|worker" >&2; exit 1 ;;
esac
[ ${#MEMBERS[@]} -gt 0 ] || MEMBERS=("zavodil.$SUFFIX")
FIRST="${MEMBERS[0]}"

read -r HASH HEX SIZE DEPOSIT < <(python3 -I -c '
import hashlib, sys
data = open(sys.argv[1], "rb").read()
digest = hashlib.sha256(data).digest()
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = int.from_bytes(digest, "big"); b58 = ""
while n:
    n, r = divmod(n, 58); b58 = alphabet[r] + b58
b58 = "1" * (len(digest) - len(digest.lstrip(b"\0"))) + b58
# storage: 10^19 yoctoNEAR per byte, plus 10% for the record around the bytes
print(b58, digest.hex(), len(data), f"{len(data) * 1e19 * 1.1 / 1e24:.4f}")
' "$WASM")

SIGN="network-config $NETWORK sign-with-legacy-keychain send"
VIEW="network-config $NETWORK now"
ACTION="{\"action\":{\"Upgrade\":{\"target\":\"$TARGET_ACC\",\"code_hash\":\"$HASH\",\"migrate\":$MIGRATE}}}"

cat <<EOF
# Upgrade $TARGET_ACC through $DAO ($NETWORK)
# wasm      $WASM
# size      $SIZE bytes
# sha256    $HEX
# code hash $HASH   (the account reports this after the deploy)
# migrate   $MIGRATE

# 1. Store the blob (deposit refunded when the upgrade executes)
near contract call-function as-transaction $DAO store_blob file-args $WASM prepaid-gas '100 Tgas' attached-deposit '$DEPOSIT NEAR' sign-as $FIRST $SIGN

# check: storer, deposit, size
near contract call-function as-read-only $DAO get_blob json-args '{"hash":"$HASH"}' $VIEW

# 2. Propose (0.1 NEAR covers the proposal's storage, the rest is refunded). The return value is <ID>
near contract call-function as-transaction $DAO propose json-args '$ACTION' prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as $FIRST $SIGN

# 3. Votes
EOF
for m in "${MEMBERS[@]}"; do
    echo "near contract call-function as-transaction $DAO vote json-args '{\"proposal_id\":<ID>,\"approve\":true}' prepaid-gas '100 Tgas' attached-deposit '0 NEAR' sign-as $m $SIGN"
done
cat <<EOF

# status Approved; executable_after = when execute is allowed
near contract call-function as-read-only $DAO get_gov_proposal json-args '{"proposal_id":<ID>}' $VIEW

# 4. Execute (any member, after the delay)
near contract call-function as-transaction $DAO execute json-args '{"proposal_id":<ID>}' prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as $FIRST $SIGN

# 5. Check: code hash = $HASH, proposal Executed, blob gone (null)
near account view-account-summary $TARGET_ACC $VIEW
near contract call-function as-read-only $DAO get_gov_proposal json-args '{"proposal_id":<ID>}' $VIEW
near contract call-function as-read-only $DAO get_blob json-args '{"hash":"$HASH"}' $VIEW
EOF
