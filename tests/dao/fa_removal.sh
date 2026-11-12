#!/usr/bin/env bash
# Delete every full-access key on the main, DAO and register test accounts, then run the
# upgrade and governance suites again: everything must still work through the DAO alone.
# IRREVERSIBLE for those accounts — no key can be added back. Testnet only. Run with --yes.

source "$(dirname "$0")/lib.sh"

[ "${1:-}" = "--yes" ] || { echo "Deletes the full-access keys of $MAIN, $DAO, $WORKER for good. Run with --yes."; exit 1; }

fa_keys() {
    rpc_query "{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$1\"}" \
        | python3 -I -c 'import sys,json
for k in json.load(sys.stdin)["result"]["keys"]:
    if k["access_key"]["permission"]=="FullAccess": print(k["public_key"])'
}

step "delete full-access keys"
for acc in "$MAIN" "$DAO" "$WORKER"; do
    for pk in $(fa_keys "$acc"); do
        near account delete-keys "$acc" public-keys "$pk" network-config "$NETWORK" \
            sign-with-legacy-keychain send >/dev/null 2>&1 \
            && ok "$acc: deleted ${pk:0:16}…" || bad "$acc: delete ${pk:0:16}…"
    done
    sleep 2
    [ -z "$(fa_keys "$acc")" ] && ok "$acc has no full-access key" || bad "$acc still has a full-access key"
done

step "the suites, without full-access keys"
NO_FA_KEYS=1 bash "$(dirname "$0")/upgrade_e2e.sh" || FAIL=$((FAIL + 1))
NO_FA_KEYS=1 bash "$(dirname "$0")/governance_e2e.sh" || FAIL=$((FAIL + 1))

summary
