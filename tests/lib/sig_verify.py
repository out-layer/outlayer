#!/usr/bin/env python3
"""Check a wallet signature against the wallet's own address — the suites' proof that a signature
is the wallet's, not just a value of the right shape.

  sig_verify.py eip191  <address> <signature-hex> <message>
  sig_verify.py eip712  <address> <signature-hex> <typed-data-json>
  sig_verify.py evmtx   <address> <signature-hex> <unsigned-typed-tx-hex>
  sig_verify.py solana  <address-base58> <signature> <message-hex>
  sig_verify.py selftest

EVM: the address recovered from the signature (secp256k1, v = 27/28 or 0/1) must equal <address>.
A typed transaction (EIP-2718: 0x01, 0x02, …) is signed over keccak256 of its unsigned bytes.
Solana: ed25519 over the message bytes, with the key <address> names; the signature is hex or
base58 (64 bytes).

Prints one line and exits 0 when the signature is the address's, 1 when it is not, 2 on bad input.
Needs `coincurve`, `pycryptodome` (keccak) and `pynacl`.
"""
import json
import sys

from Crypto.Hash import keccak


def k256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


# ---- EIP-712 ---------------------------------------------------------------------------------

def _deps(primary, types, found=None):
    found = found if found is not None else []
    if primary in found or primary not in types:
        return found
    found.append(primary)
    for f in types[primary]:
        _deps(f["type"].rstrip("[]").split("[")[0], types, found)
    return found


def _encode_type(primary, types):
    deps = _deps(primary, types)
    deps = [primary] + sorted(d for d in deps if d != primary)
    return "".join(f"{d}({','.join(f['type'] + ' ' + f['name'] for f in types[d])})" for d in deps)


def _type_hash(primary, types):
    return k256(_encode_type(primary, types).encode())


def _int(v):
    if isinstance(v, str):
        return int(v, 16) if v.startswith(("0x", "0X")) else int(v)
    return int(v)


def _encode_value(t, v, types):
    if t in types:
        return k256(_encode_data(t, v, types))
    if t.endswith("]"):
        inner = t[: t.rindex("[")]
        return k256(b"".join(_encode_value(inner, x, types) for x in v))
    if t == "string":
        return k256(v.encode())
    if t == "bytes":
        return k256(bytes.fromhex(v[2:] if v.startswith("0x") else v))
    if t == "address":
        return bytes(12) + bytes.fromhex(v[2:].rjust(40, "0"))
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if t.startswith("uint"):
        return _int(v).to_bytes(32, "big")
    if t.startswith("int"):
        return (_int(v) % (1 << 256)).to_bytes(32, "big")
    if t.startswith("bytes"):
        raw = bytes.fromhex(v[2:] if v.startswith("0x") else v)
        return raw.ljust(32, b"\0")
    raise ValueError(f"EIP-712 type {t!r} not handled")


def _encode_data(primary, data, types):
    out = _type_hash(primary, types)
    for f in types[primary]:
        out += _encode_value(f["type"], data[f["name"]], types)
    return out


def eip712_digest(typed: dict) -> bytes:
    types = dict(typed["types"])
    domain = k256(_encode_data("EIP712Domain", typed["domain"], types))
    msg = k256(_encode_data(typed["primaryType"], typed["message"], types))
    return k256(b"\x19\x01" + domain + msg)


# ---- secp256k1 recovery ----------------------------------------------------------------------

def recover_address(digest: bytes, sig_hex: str) -> str:
    from coincurve import PublicKey

    sig = bytes.fromhex(sig_hex[2:] if sig_hex.startswith("0x") else sig_hex)
    if len(sig) != 65:
        raise ValueError(f"signature is {len(sig)} bytes, not 65")
    v = sig[64]
    recid = v - 27 if v >= 27 else v
    if recid not in (0, 1):
        raise ValueError(f"v = {v} is not 27/28 or 0/1")
    pub = PublicKey.from_signature_and_message(sig[:64] + bytes([recid]), digest, hasher=None)
    return "0x" + k256(pub.format(compressed=False)[1:])[-20:].hex()


def eip191_digest(message: str) -> bytes:
    m = message.encode()
    return k256(b"\x19Ethereum Signed Message:\n" + str(len(m)).encode() + m)


# ---- ed25519 (Solana) ------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


def solana_ok(address: str, sig: str, message: bytes) -> bool:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    pub = b58decode(address)
    s = sig[2:] if sig.startswith("0x") else sig
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        raw = b58decode(s)
    if len(pub) != 32 or len(raw) != 64:
        raise ValueError(f"key {len(pub)} bytes / signature {len(raw)} bytes, not 32 / 64")
    try:
        VerifyKey(pub).verify(message, raw)
        return True
    except BadSignatureError:
        return False


# ---- self-test -------------------------------------------------------------------------------

def selftest() -> None:
    # The example of EIP-712 itself: its digest is published in the EIP.
    mail = {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
            "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"}, {"name": "contents", "type": "string"}],
        },
        "primaryType": "Mail",
        "domain": {"name": "Ether Mail", "version": "1", "chainId": 1,
                   "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
        "message": {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                    "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                    "contents": "Hello, Bob!"},
    }
    want = "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    got = eip712_digest(mail).hex()
    assert got == want, f"EIP-712 digest {got} != the EIP's {want}"
    # The EIP's signer is cow (private key keccak256("cow")): its signature must recover to it.
    from coincurve import PrivateKey

    pk = PrivateKey(k256(b"cow"))
    cow = "0x" + k256(pk.public_key.format(compressed=False)[1:])[-20:].hex()
    assert cow == "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826", cow
    for digest in (eip712_digest(mail), eip191_digest("hello")):
        rs = pk.sign_recoverable(digest, hasher=None)
        sig = rs[:64].hex() + format(rs[64] + 27, "02x")
        assert recover_address(digest, sig) == cow
        assert recover_address(k256(digest), sig) != cow  # another digest: another signer
    from nacl.signing import SigningKey

    sk = SigningKey(bytes(range(32)))
    pub = sk.verify_key.encode()
    n = int.from_bytes(pub, "big")
    addr = ""
    while n:
        n, r = divmod(n, 58)
        addr = B58[r] + addr
    sm = sk.sign(b"msg").signature.hex()
    assert solana_ok(addr, sm, b"msg") and not solana_ok(addr, sm, b"msh")
    print("selftest ok: EIP-712 digest of the EIP's example, ecrecover, ed25519")


def main(argv) -> int:
    if len(argv) == 2 and argv[1] == "selftest":
        selftest()
        return 0
    if len(argv) != 5:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    kind, address, sig, payload = argv[1:]
    try:
        if kind == "solana":
            ok = solana_ok(address, sig, bytes.fromhex(payload[2:] if payload.startswith("0x") else payload))
            print(f"ed25519 signature {'IS' if ok else 'is NOT'} by {address}")
            return 0 if ok else 1
        if kind == "eip191":
            digest = eip191_digest(payload)
        elif kind == "eip712":
            digest = eip712_digest(json.loads(payload))
        elif kind == "evmtx":
            raw = bytes.fromhex(payload[2:] if payload.startswith("0x") else payload)
            if not raw or raw[0] >= 0x7F:
                raise ValueError("not a typed (EIP-2718) transaction")
            digest = k256(raw)
        else:
            raise ValueError(f"unknown kind {kind!r}")
        signer = recover_address(digest, sig)
    except (ValueError, KeyError, TypeError) as e:
        print(f"bad input: {e}")
        return 2
    ok = signer == address.lower()
    print(f"recovered {signer} {'==' if ok else '!='} {address.lower()}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
