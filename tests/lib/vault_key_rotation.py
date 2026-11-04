#!/usr/bin/env python3
"""Body of tests/vault_key_rotation_e2e.sh — run through it, not directly."""
import hashlib, hmac, json, os, re, subprocess, sys, time, urllib.request, urllib.error, uuid

API = os.environ["COORDINATOR_URL"]
RPC = os.environ["RPC_URL"]
PARENT = os.environ["PARENT"]
VAULT = os.environ["VAULT"]
CONTRACT = os.environ["CONTRACT_ID"]
NETWORK = os.environ["NETWORK"]
ONLY = {s for s in os.environ.get("ONLY", "").split(",") if s}
NEAR_LOG = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"vault_key_rotation.{os.getpid()}.near.log")

PASS, FAILED, FAILED_NAMES = 0, 0, []
CLEANUP = []  # (what, fn) — run in reverse at exit

def log(s):  print(f"\n\033[36m▶ {s}\033[0m", file=sys.stderr)
def note(s): print(f"\033[35m• {s}\033[0m", file=sys.stderr)
def warn(s): print(f"\033[33m⚠ {s}\033[0m", file=sys.stderr)
def ok(cond, label):
    global PASS, FAILED
    if cond:
        PASS += 1; print(f"\033[32m✓ {label}\033[0m", file=sys.stderr)
    else:
        FAILED += 1; FAILED_NAMES.append(label); print(f"\033[31m✗ {label}\033[0m", file=sys.stderr)
    return cond

def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def pre(k): return sha(k)[:8] + "…"

# ── the customer's derivation ────────────────────────────────────────────────
def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); okm += t; i += 1
    return okm[:length]

def derive_wk(master, seed): return "wk_" + hkdf_sha256(master, b"outlayer-wk-v1", seed.encode()).hex()

def expected_child_id(parent_wallet_id, seed_hex, vault):
    h = hashlib.sha256(b"outlayer:deterministic-wallet-id:" + parent_wallet_id.encode()
                       + b":" + seed_hex.encode() + b"\0vault:" + vault.encode()).digest()
    return str(uuid.UUID(bytes=h[:16]))

# ── clients ──────────────────────────────────────────────────────────────────
def api(method, path, key=None, body=None):
    headers = {"Content-Type": "application/json", "User-Agent": "vault_key_rotation_e2e"}
    if key: headers["Authorization"] = "Bearer " + key
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(6):
        req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code == 429:
                time.sleep(10 * (attempt + 1)); continue
            try: return e.code, json.loads(raw)
            except Exception: return e.code, raw.decode(errors="replace")[:300]
    return 429, "rate limited"

def rpc_view(acct, method, args):
    body = {"jsonrpc": "2.0", "id": 1, "method": "query", "params": {
        "request_type": "call_function", "finality": "final", "account_id": acct,
        "method_name": method, "args_base64": __import__("base64").b64encode(json.dumps(args).encode()).decode()}}
    r = json.load(urllib.request.urlopen(urllib.request.Request(RPC, json.dumps(body).encode(), {"content-type": "application/json"}), timeout=30))
    res = r.get("result", {})
    return json.loads(bytes(res["result"]).decode()) if "result" in res else None

def native_balance(acct):
    body = {"jsonrpc": "2.0", "id": 1, "method": "query", "params": {"request_type": "view_account", "finality": "final", "account_id": acct}}
    r = json.load(urllib.request.urlopen(urllib.request.Request(RPC, json.dumps(body).encode(), {"content-type": "application/json"}), timeout=30))
    return int(r["result"]["amount"]) if "result" in r and "amount" in r["result"] else 0

def near(*args):
    """near-cli-rs, non-interactive, keychain-signed. Output goes to a file; a
    failure reports the contract panic or the first error line, never the URL."""
    for attempt in (1, 2):
        p = subprocess.run(["near", *args, "network-config", NETWORK, "sign-with-keychain", "send"],
                           capture_output=True, text=True, timeout=240)
        out = p.stdout + p.stderr
        with open(NEAR_LOG, "a") as f: f.write(" ".join(args[:4]) + f" (attempt {attempt})\n" + out + "\n")
        why = (re.search(r"Smart contract panicked: [^\"\n]{1,200}", out)
               or re.search(r"(Transaction has expired|Tx not found|TIMEOUT_ERROR|timed out)[^\n]{0,80}", out)
               or re.search(r"^(Error|error):.{0,200}", out, re.M))
        if p.returncode == 0 and not why:
            return True, ""
        # A stale block hash or a lost receipt is the RPC's, not the contract's: once more.
        if attempt == 1 and why and re.search(r"expired|Tx not found|TIMEOUT|timed out", why.group(0)):
            time.sleep(5); continue
        return False, why.group(0) if why else f"rc={p.returncode}"

def call_contract(method, args, deposit="0 NEAR", gas="100.0 Tgas"):
    return near("contract", "call-function", "as-transaction", CONTRACT, method, "json-args", json.dumps(args),
                "prepaid-gas", gas, "attached-deposit", deposit, "sign-as", PARENT)

def fund(addr, amount): return near("--quiet", "tokens", PARENT, "send-near", addr, amount)

def address(key):
    st, a = api("GET", "/wallet/v1/address?chain=near", key)
    a = a if isinstance(a, dict) else {}
    return st, a.get("address"), a.get("vault_id")

POLICY_PUBKEYS = set()  # every wallet pubkey a policy was stored under: each deposit is reclaimed at exit

def store_policy(key, wallet_id, policy):
    """encrypt-policy → sign-policy (caller = PARENT) → store_wallet_policy by PARENT."""
    st, enc = api("POST", "/wallet/v1/encrypt-policy", key, {"wallet_id": wallet_id, **policy})
    if st != 200: return False, f"encrypt-policy {st}: {enc}"
    st, sg = api("POST", "/wallet/v1/sign-policy", key, {"encrypted_data": enc["encrypted_base64"], "caller": PARENT})
    if st != 200: return False, f"sign-policy {st}: {sg}"
    POLICY_PUBKEYS.add(sg["public_key_hex"])
    done, why = call_contract("store_wallet_policy", {"wallet_pubkey": "ed25519:" + sg["public_key_hex"],
                                                      "encrypted_data": enc["encrypted_base64"],
                                                      "wallet_signature": sg["signature_hex"]}, deposit="0.1 NEAR")
    return done, why

def wait_key(key, want=200, secs=240):
    t0 = time.time()
    while time.time() - t0 < secs:
        st, _, _ = address(key)
        if st == want: return True, int(time.time() - t0)
        time.sleep(5)
    return False, int(time.time() - t0)

def run(name):
    return not ONLY or name in ONLY

# ── R1 ───────────────────────────────────────────────────────────────────────
log(f"R1 parent under {VAULT}, sub-agents keyed as the customer does ({API})")
st, r = api("POST", "/register", body={"vault_id": VAULT})
if st != 200: sys.exit(f"register under {VAULT} -> {st}: {r}")
PK1, PWID, PADDR = r["api_key"], r["wallet_id"], r["near_account_id"]
note(f"parent wallet {PWID} address {PADDR} key {pre(PK1)}")
CLEANUP.append(("policy storage deposits", lambda: [call_contract("delete_wallet_policy", {"wallet_pubkey": "ed25519:" + pk}, gas="30 Tgas")[1] or pk[:8] for pk in POLICY_PUBKEYS]))
st, addr, vault = address(PK1)
ok(st == 200 and addr == PADDR and vault == VAULT, f"R1 parent key v1: address {addr}, vault {vault}")

SEEDS = ["platform:fees", "x402:treasury", f"acct:{uuid.uuid4()}", f"job:{uuid.uuid4()}"]
FUNDED = SEEDS[2]
M1, M2 = os.urandom(32), os.urandom(32)
child = {}
for s in SEEDS:
    wk1, sh = derive_wk(M1, s), sha(s)
    st, r = api("PUT", "/wallet/v1/api-key", PK1, {"seed": sh, "key_hash": sha(wk1)})
    if not ok(st == 200 and isinstance(r, dict), f"R1 {s[:13]} registered -> {st}"): continue
    ok(r["wallet_id"] == expected_child_id(PWID, sh, VAULT) and r.get("vault_id") == VAULT,
       f"R1 {s[:13]} wallet {r['wallet_id']} under {r.get('vault_id')}")
    st, caddr, _ = address(wk1)
    ok(st == 200 and caddr == r["near_account_id"], f"R1 {s[:13]} v1 key works, address {caddr}")
    child[s] = {"wid": r["wallet_id"], "addr": r["near_account_id"], "wk1": wk1, "sh": sh}

F = child[FUNDED]
done, why = fund(F["addr"], "0.02 NEAR")
ok(done, f"R1 fund {F['addr']} with 0.02 NEAR from {PARENT} {why}")
CLEANUP.append(("sub-agent funds → parent", lambda: api("POST", "/wallet/v1/delete", F.get("wk2") or F["wk1"], {"beneficiary": PARENT, "chain": "near"})))
bal0 = native_balance(F["addr"])
st, r = api("POST", "/wallet/v1/transfer", F["wk1"], {"chain": "near", "to": PARENT, "amount": "1000000000000000000000"})
ok(st == 200 and isinstance(r, dict) and r.get("status") in ("success", "completed") and r.get("tx_hash"),
   f"R1 funded sub-agent moves 0.001 NEAR with its v1 key -> {st} {r.get('status') if isinstance(r, dict) else r}")

# ── R2 ───────────────────────────────────────────────────────────────────────
PK2 = "wk_" + os.urandom(32).hex()
if run("R2"):
    log(f"R2 replace the parent key through the owner policy ({PARENT}), two saves")
    done, why = store_policy(PK1, PWID, {"rules": {}, "authorized_key_hashes": [sha(PK1), sha(PK2)]})
    ok(done, f"R2 save 1: policy names [old {pre(PK1)}, new {pre(PK2)}] {why}")
    accepted, secs = wait_key(PK2)
    ok(accepted, f"R2 new parent key accepted after {secs} s")
    st, _, _ = address(PK1)
    ok(st == 200, f"R2 old key still works between the saves -> {st}")
    done, why = store_policy(PK2, PWID, {"rules": {}, "authorized_key_hashes": [sha(PK2)]})
    ok(done, f"R2 save 2: policy names [new] only, saved with the new key {why}")
    gone, secs = wait_key(PK1, want=401)
    ok(gone, f"R2 old parent key refused after {secs} s")
    pol = rpc_view(CONTRACT, "get_wallet_policy", {"wallet_pubkey": "ed25519:" + PADDR})
    ok(pol and pol.get("owner") == PARENT, f"R2 on-chain owner of the parent wallet is {pol.get('owner') if pol else None}")

# ── R3 ───────────────────────────────────────────────────────────────────────
if run("R3"):
    log("R3 what the new parent key sees")
    st, addr, vault = address(PK2)
    ok(st == 200 and vault == VAULT, f"R3 vault_id with the new key: {vault!r}")
    ok(addr == PADDR, f"R3 parent address with the new key: {addr} (was {PADDR})")
    for s, c in child.items():
        probe = "wk_" + os.urandom(32).hex()   # a throwaway hash: the lookup must not mint a new wallet
        st, r = api("PUT", "/wallet/v1/api-key", PK2, {"seed": c["sh"], "key_hash": sha(probe)})
        same = st == 200 and r.get("wallet_id") == c["wid"] and r.get("near_account_id") == c["addr"] and r.get("vault_id") == VAULT
        ok(same, f"R3 {s[:13]} resolves to the same wallet {r.get('wallet_id') if isinstance(r, dict) else r}")
        if same:
            st, _ = api("DELETE", f"/wallet/v1/api-key/{sha(probe)}", probe)
            ok(st == 200, f"R3 {s[:13]} probe key removed again -> {st}")

# ── R4 ───────────────────────────────────────────────────────────────────────
if run("R4"):
    log("R4 rotate the sub-agent master: PUT v2 with the new parent, DELETE v1 with the v2 key")
    for s, c in child.items():
        wk2 = derive_wk(M2, s)
        st, r = api("PUT", "/wallet/v1/api-key", PK2, {"seed": c["sh"], "key_hash": sha(wk2)})
        ok(st == 200 and r.get("wallet_id") == c["wid"] and r.get("near_account_id") == c["addr"], f"R4 {s[:13]} PUT v2 -> {st}: same wallet")
        st, _ = api("DELETE", f"/wallet/v1/api-key/{sha(c['wk1'])}", PK2)
        ok(st == 400, f"R4 {s[:13]} the parent cannot revoke the child's key -> {st}")
        st, r = api("DELETE", f"/wallet/v1/api-key/{sha(c['wk1'])}", wk2)
        ok(st == 200 and isinstance(r, dict) and r.get("revoked") is True, f"R4 {s[:13]} DELETE v1 with the v2 key -> {st}")
        st, _, _ = address(c["wk1"])
        ok(st == 401, f"R4 {s[:13]} v1 key refused -> {st}")
        st, caddr, v = address(wk2)
        ok(st == 200 and caddr == c["addr"] and v == VAULT, f"R4 {s[:13]} v2 key: same address, vault {v}")
        c["wk2"] = wk2
    bal1 = native_balance(F["addr"])
    st, r = api("POST", "/wallet/v1/transfer", F["wk2"], {"chain": "near", "to": PARENT, "amount": "1000000000000000000000"})
    ok(st == 200 and isinstance(r, dict) and r.get("status") in ("success", "completed") and r.get("tx_hash"),
       f"R4 funded sub-agent moves 0.001 NEAR with its v2 key from the same address -> {st}")
    time.sleep(3)
    bal2 = native_balance(F["addr"])
    ok(0 < bal1 - bal2 < 2_000_000_000_000_000_000_000, f"R4 the balance moved from {F['addr']}: {bal1} → {bal2} yocto")
    # re-running the rotation script is harmless
    c = child[FUNDED]
    st, r = api("PUT", "/wallet/v1/api-key", PK2, {"seed": c["sh"], "key_hash": sha(c["wk2"])})
    ok(st == 200 and r.get("wallet_id") == c["wid"], f"R4 PUT of the registered v2 hash again -> {st}")
    st, _ = api("DELETE", f"/wallet/v1/api-key/{sha(c['wk1'])}", c["wk2"])
    ok(st == 400, f"R4 DELETE of the already revoked v1 hash again -> {st}")
    st, _ = api("DELETE", f"/wallet/v1/api-key/{sha(c['wk2'])}", c["wk2"])
    ok(st == 409, f"R4 the last key of a wallet cannot be revoked -> {st}")
    st, _ = api("PUT", "/wallet/v1/api-key", PK1, {"seed": sha("acct:anyone"), "key_hash": sha("wk_x")})
    ok(st == 401, f"R4 the old parent key can register nothing -> {st}")
    st, _ = api("POST", "/wallet/v1/sign-policy", PK1, {"encrypted_data": "AAAA", "caller": PARENT})
    ok(st == 401, f"R4 the old parent key cannot sign a policy -> {st}")

# ── R5 ───────────────────────────────────────────────────────────────────────
if run("R5"):
    log("R5 negatives")
    c = child[FUNDED]
    # a policy of the parent naming the funded child's key: the child's key stays the child's
    done, why = store_policy(PK2, PWID, {"rules": {}, "authorized_key_hashes": [sha(PK2), sha(c["wk2"])]})
    ok(done, f"R5 parent policy names its key and the child's {why}")
    time.sleep(8)
    st, caddr, v = address(c["wk2"])
    ok(st == 200 and caddr == c["addr"] and v == VAULT, f"R5 the child's key still opens the child ({caddr}), vault {v}")
    st, addr, v = address(PK2)
    ok(st == 200 and addr == PADDR and v == VAULT, f"R5 the parent key unchanged")
    # freeze: money stops, the owner can still save a policy, the new key still authenticates
    done, why = call_contract("freeze_wallet", {"wallet_pubkey": "ed25519:" + PADDR})
    ok(done, f"R5 freeze_wallet by the owner {why}")
    time.sleep(8)
    st, r = api("POST", "/wallet/v1/transfer", PK2, {"chain": "near", "to": PARENT, "amount": "1"})
    ok(st == 403 and isinstance(r, dict) and r.get("error") == "wallet_frozen", f"R5 a transfer under freeze -> {st} {r.get('error') if isinstance(r, dict) else r}")
    done, why = store_policy(PK2, PWID, {"rules": {}, "authorized_key_hashes": [sha(PK2)]})
    ok(done, f"R5 the owner saves a policy while frozen {why}")
    time.sleep(8)
    st, addr, v = address(PK2)
    ok(st == 200 and addr == PADDR and v == VAULT, f"R5 the key still authenticates under freeze, vault {v}")
    pol = rpc_view(CONTRACT, "get_wallet_policy", {"wallet_pubkey": "ed25519:" + PADDR})
    ok(pol and pol.get("frozen") is True, "R5 the policy save kept the wallet frozen")
    done, why = call_contract("unfreeze_wallet", {"wallet_pubkey": "ed25519:" + PADDR})
    ok(done, f"R5 unfreeze_wallet {why}")
    # the self-lockout: an empty list after a rotation
    done, why = store_policy(PK2, PWID, {"rules": {}, "authorized_key_hashes": []})
    ok(done, f"R5 policy with an EMPTY authorized_key_hashes {why}")
    gone, secs = wait_key(PK2, want=401, secs=60)
    st1, _, _ = address(PK1)
    note(f"R5 empty list after a rotation: new key -> {'401' if gone else '200'}, old key -> {st1} (known: nothing comes back; the customer keeps the current hash listed)")
    ok(gone and st1 == 401, "R5 an empty authorized_key_hashes after a rotation leaves no live key (documented in ROTATION.md §6)")
    if gone:
        warn("R5 the parent is now locked out by design; its sub-agents keep working on their own keys")
        st, caddr, v = address(c["wk2"])
        ok(st == 200 and caddr == c["addr"], "R5 the funded sub-agent still works on its v2 key")

# ── cleanup ──────────────────────────────────────────────────────────────────
log("Cleanup")
for what, fn in reversed(CLEANUP):
    try:
        res = fn()
        note(f"{what}: {res if not isinstance(res, tuple) else (res[1] or 'ok')}")
    except Exception as e:
        warn(f"{what}: {e}")
time.sleep(3)
left = native_balance(F["addr"])
ok(left == 0, f"sub-agent {F['addr']} swept to {PARENT} (left {left} yocto)")

print(f"\n{PASS} passed, {FAILED} failed" + (": " + "; ".join(FAILED_NAMES) if FAILED_NAMES else ""), file=sys.stderr)
note(f"near-cli output in {NEAR_LOG}")
sys.exit(1 if FAILED else 0)
