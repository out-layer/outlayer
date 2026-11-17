#!/usr/bin/env bash
# Registration hardening, live on the testnet contracts (after the DAO, register and main contract
# release that carries it):
#   H1  an ed25519 key of small order is refused before its quote is read: by the register
#       contract (register_worker_key) and by the DAO (submit_keystore_registration)
#   H2  a key remove_worker_keys took off stays removed: registering it again is refused, whatever
#       quote comes with it; another key goes on to the quote checks
#   H3  a removed worker build is not approved again: a DAO Call that adds it, decided after the
#       removal, executes and the build stays off the list
#   H4  the owner cannot cancel a DAO Call that revokes a worker build or key; members vote it down
#   H5  the main contract refuses a wallet key of small order before it checks the signature
#   H6  (PSQL_CMD + DB_WRITE=1) the coordinator ends the TEE sessions of a key that is not on the
#       operator account within one sweep (≤ 6 min); a live worker renews its session (a new row
#       every 20 min)
# Every throwaway build is random; nothing a live worker uses is touched. H3 waits the governance
# delay twice.
#
#   TEST_ROOT=outlayer.testnet M1=zavodil2.testnet M2=zavodil.testnet M3=zavodil3.testnet \
#     bash tests/dao/registration_hardening_e2e.sh --apply
#   ONLY=H1,H2 … --apply         a subset
#   PSQL_CMD=.idea/testnet-runners/psql_testnet.sh DB_WRITE=1 ONLY=H6 … --apply
[ "${1:-}" = "--apply" ] || { sed -n 2,22p "$0"; exit 0; }
shift

source "$(dirname "$0")/lib.sh"
set +e
# lib.sh's `call`, resending a transaction refused before it reached a block (expired, or its
# nonce taken): that changed nothing, and a check must not read it as the contract's answer.
call() {
    local signer="$1" acc="$2" method="$3" args="$4" gas="${5:-100 Tgas}" dep="${6:-0 NEAR}" try rc
    for try in 1 2 3; do
        LAST_OUT=$(near contract call-function as-transaction "$acc" "$method" json-args "$args" \
            prepaid-gas "$gas" attached-deposit "$dep" sign-as "$signer" \
            network-config "$NETWORK" sign-with-legacy-keychain send 2>&1); rc=$?
        printf '%s' "$LAST_OUT" | grep -qE 'Transaction has expired|must be account\[access_key\]\.nonce' || return $rc
        sleep 3
    done
    return $rc
}
want() { [ -z "${ONLY:-}" ] || [[ ",$ONLY," == *",$1,"* ]]; }
vote() { call "$1" "$DAO" vote "{\"proposal_id\":$2,\"approve\":$3}"; }

INIT_WORKER=$(view "$WORKER" get_init_worker_account | tr -d '\n "')
INIT_KEYSTORE=$(view "$DAO" get_config | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["init_account_id"])')
DELAY=$(view "$DAO" get_gov_delay_sec | tr -d '\n ')
b58() { python3 -I -c 'import sys
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
b=bytes.fromhex(sys.argv[1]); n=int.from_bytes(b,"big"); s=""
while n: n,r=divmod(n,58); s=A[r]+s
print("1"*(len(b)-len(b.lstrip(b"\0")))+s)' "$1"; }
rand_hex() { python3 -I -c "import os; print(os.urandom($1).hex())"; }
ORDER8="26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"   # an order-8 point, sign bit set
SMALL_KEYS=("ed25519:$(b58 "$(printf '0%.0s' {1..64})")" "ed25519:$(b58 "01$(printf '0%.0s' {1..62})")" "ed25519:$(b58 "$ORDER8")")
echo "  register init $INIT_WORKER, DAO init $INIT_KEYSTORE, delay $DELAY s"

if want H1; then
    step "H1 a key of small order is refused before its quote"
    for k in "${SMALL_KEYS[@]}"; do
        expect_refused "small order" "$INIT_WORKER" "$WORKER" register_worker_key "{\"public_key\":\"$k\",\"tdx_quote_hex\":\"00\"}" "300 Tgas"
        expect_refused "small order" "$INIT_KEYSTORE" "$DAO" submit_keystore_registration "{\"public_key\":\"$k\",\"tdx_quote_hex\":\"00\",\"app_id\":null,\"event_log\":[]}" "300 Tgas"
    done
    real="ed25519:$(b58 "$(rand_hex 32)")"
    if call "$INIT_WORKER" "$WORKER" register_worker_key "{\"public_key\":\"$real\",\"tdx_quote_hex\":\"00\"}" "300 Tgas"; then
        bad "a key with a made-up quote registered"
    else
        printf '%s' "$LAST_OUT" | grep -q "small order" && bad "a random key was taken for one of small order" \
            || ok "a random key goes on to the quote checks: $(printf '%s' "$LAST_OUT" | grep -aoE 'Smart contract panicked: [^"]*' | head -1 | cut -c1-120)"
    fi
fi

if want H2; then
    step "H2 a removed key stays removed"
    gone="ed25519:$(b58 "$(rand_hex 32)")"; other="ed25519:$(b58 "$(rand_hex 32)")"
    # The key is not on the account: its DeleteKey fails on its own, the record of the removal stays.
    call "$OWNER" "$WORKER" remove_worker_keys "{\"public_keys\":[\"$gone\"]}" "100 Tgas" \
        && ok "the owner removed $gone" || bad "remove_worker_keys: $(printf '%s' "$LAST_OUT" | grep -aE 'panicked|Error' | head -1 | cut -c1-160)"
    expect_refused "was removed" "$INIT_WORKER" "$WORKER" register_worker_key "{\"public_key\":\"$gone\",\"tdx_quote_hex\":\"00\"}" "300 Tgas"
    if call "$INIT_WORKER" "$WORKER" register_worker_key "{\"public_key\":\"$other\",\"tdx_quote_hex\":\"00\"}" "300 Tgas"; then
        bad "a key with a made-up quote registered"
    else
        printf '%s' "$LAST_OUT" | grep -q "was removed" && bad "a key never removed was refused as removed" \
            || ok "a key never removed goes on to the quote checks"
    fi
fi

# A Call to the register contract, as dao_gov.sh builds one.
call_action() {
    python3 -I -c 'import json,sys,base64
print(json.dumps({"Call":{"target":sys.argv[1],"method":sys.argv[2],"args":base64.b64encode(sys.argv[3].encode()).decode(),"deposit":"0","gas_tgas":30}}))' "$1" "$2" "$3"
}
wait_exec() {   # wait until proposal $1 is executable, then execute it
    local after w
    after=$(view "$DAO" get_gov_proposal "{\"proposal_id\":$1}" | python3 -I -c 'import sys,json; print(json.load(sys.stdin).get("executable_after") or 0)')
    w=$(python3 -I -c "import time,sys; print(max(0, int(int(sys.argv[1])/1e9 - time.time()) + 10))" "$after")
    echo "  waiting ${w} s for #$1"; sleep "$w"
    call "$M3" "$DAO" execute "{\"proposal_id\":$1}" "300 Tgas"
}

if want H3; then
    step "H3 a removed build is not approved again"
    T=$(python3 -I -c 'import os,json; h=lambda: os.urandom(48).hex(); print(json.dumps({"mrtd":h(),"rtmr0":h(),"rtmr1":h(),"rtmr2":h(),"rtmr3":h()}))')
    listed() { view "$WORKER" is_measurements_approved "{\"measurements\":$T}" | tr -d '\n '; }
    p=$(propose "$M1" "$(call_action "$WORKER" add_approved_measurements "{\"measurements\":$T,\"clear_others\":false}")"); vote "$M2" "$p" true
    wait_exec "$p" && [ "$(listed)" = true ] && ok "#$p approved a throwaway build" || bad "#$p: $(gov_status "$p"), listed $(listed)"
    call "$OWNER" "$WORKER" remove_approved_measurements "{\"measurements\":$T}" && [ "$(listed)" = false ] \
        && ok "the owner removed it" || bad "remove: listed $(listed)"
    p=$(propose "$M1" "$(call_action "$WORKER" add_approved_measurements "{\"measurements\":$T,\"clear_others\":false}")"); vote "$M2" "$p" true
    wait_exec "$p"
    [ "$(listed)" = false ] && ok "#$p ($(gov_status "$p")) did not bring it back: $(printf '%s' "$LAST_OUT" | grep -aoE 'a removed build is not approved again' | head -1)" \
        || bad "the removed build is approved again by #$p"
fi


if want H4; then
    step "H4 the owner cannot cancel a revocation of a worker build or key"
    # Aimed at an account that is not the register contract: these proposals are voted down, and
    # one that executed by mistake would change nothing.
    TGT="no-register-$(date +%s).testnet"
    for m in remove_approved_measurements clear_all_approved_measurements remove_worker_keys; do
        p=$(propose "$M1" "$(call_action "$TGT" "$m" '{}')")
        expect_refused "revocation of a worker build or key cannot be cancelled by the owner" "$OWNER" "$DAO" cancel "{\"proposal_id\":$p}"
        vote "$M2" "$p" false; vote "$M3" "$p" false
        [ "$(gov_status "$p")" = Rejected ] && ok "#$p ($m) voted down by the members" || bad "#$p $(gov_status "$p")"
    done
fi

if want H5; then
    step "H5 the main contract refuses a wallet key of small order"
    until=$(( $(date +%s) + 600 ))
    zero_sig=$(printf '0%.0s' {1..128})
    for hex in "$(printf '0%.0s' {1..64})" "$ORDER8"; do
        expect_refused "small order" "$STRANGER" "$MAIN" store_wallet_policy \
            "{\"wallet_pubkey\":\"ed25519:$hex\",\"encrypted_data\":\"eA==\",\"wallet_signature\":\"$zero_sig\",\"version\":1,\"locked\":false,\"valid_until\":$until,\"storage_refund_to\":null}" "100 Tgas" "0.1 NEAR"
    done
fi

if want H6; then
    step "H6 coordinator TEE sessions"
    if [ -z "${PSQL_CMD:-}" ] || [ "${DB_WRITE:-}" != 1 ]; then
        echo "  skip: needs PSQL_CMD and DB_WRITE=1"
    else
        fake="ed25519:$(b58 "$(rand_hex 32)")"
        "$PSQL_CMD" "INSERT INTO worker_tee_sessions (token_hash, worker_public_key) VALUES ('e2e-sweep-$(date +%s)', '$fake')" >/dev/null
        echo "  a session for a key not on $WORKER; waiting for the sweep (≤ 6 min)"
        for i in $(seq 1 13); do
            sleep 30
            [ "$("$PSQL_CMD" "SELECT count(*) FROM worker_tee_sessions WHERE worker_public_key = '$fake' AND is_active")" = 0 ] && break
        done
        [ "$("$PSQL_CMD" "SELECT count(*) FROM worker_tee_sessions WHERE worker_public_key = '$fake' AND is_active")" = 0 ] \
            && ok "the sweep ended the session of a key not on the account" || bad "the session of $fake is still active"
        "$PSQL_CMD" "DELETE FROM worker_tee_sessions WHERE worker_public_key = '$fake'" >/dev/null
        renewing=$("$PSQL_CMD" "SELECT count(*) FROM (SELECT worker_public_key FROM worker_tee_sessions WHERE created_at > NOW() - INTERVAL '70 minutes' GROUP BY 1 HAVING count(*) >= 3) k")
        [ "${renewing:-0}" -ge 1 ] && ok "$renewing worker key(s) made 3+ sessions in 70 min: they renew" \
            || bad "no worker renewed its session in 70 min (did the workers run that long?)"
    fi
fi

summary
