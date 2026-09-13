#!/usr/bin/env python3
"""Store a secrets row OWNED BY ANOTHER ACCOUNT, which the CLI cannot do.

`outlayer secrets set` encrypts for, and signs as, the one account it is logged
in as — there is no seam for a second owner. Cross-owner fixtures therefore need
the ECIES envelope built here and the `store_secrets` signed by that owner with
near-cli. Used by the manifest-`owner` rows (A5/A6), where the author's row
belongs to an account other than the publisher.

Wire format, matching `outlayer-cli/src/crypto.rs`, `dashboard/lib/ecies.ts` and
the keystore's `decrypt_ecies` branch:

    base64( 0x01 | ephemeral_x25519_pub(32) | nonce(12) | ciphertext+tag )

X25519 ECDH → HKDF-SHA256(salt=None, info=b"outlayer-keystore-v1") → 32-byte key
→ ChaCha20-Poly1305. Any drift in the info string or the layout breaks every
encrypt/decrypt pair, so it is spelled out rather than imported.

    ./store_row_for_owner.py <project_id> <profile> <owner> <secrets-json> [--access JSON]

Prints the near-cli command to run; it does not sign anything itself, so the
signing stays visible and auditable in the caller's log.
"""
import argparse, base64, json, os, sys, urllib.error, urllib.request

HKDF_INFO = b"outlayer-keystore-v1"
ECIES_VERSION = 1


def pubkey_for(api: str, project_id: str, profile: str, owner: str, secrets_json: str) -> str:
    body = json.dumps({
        "accessor": {"type": "Project", "project_id": project_id},
        "owner": owner,
        "profile": profile,
        "secrets_json": secrets_json,
    }).encode()
    # A User-Agent is NOT optional. Cloudflare fronts these hosts and answers a
    # header-less client with `403 error code: 1010` — which reads exactly like an
    # authorisation failure and is nothing of the kind. `curl` is never filtered;
    # bare `urllib` always is.
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": "outlayer-tests/store_row_for_owner",
    }
    req = urllib.request.Request(f"{api}/secrets/pubkey", body, headers)
    try:
        answer = json.load(urllib.request.urlopen(req, timeout=40))
    except urllib.error.HTTPError as e:
        # The body carries the reason; letting the HTTPError escape hides it
        # behind a traceback and turns a five-second diagnosis into a hunt.
        detail = e.read(400).decode("utf-8", "replace")
        sys.exit(f"/secrets/pubkey answered HTTP {e.code}: {detail}")
    except Exception as e:
        sys.exit(f"/secrets/pubkey unreachable: {type(e).__name__}: {e}")
    key = answer.get("pubkey")
    if not key:
        sys.exit(f"no pubkey in the answer: {json.dumps(answer)[:300]}")
    return key


def envelope(pubkey_hex: str, plaintext: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    recipient = X25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    ephemeral = X25519PrivateKey.generate()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(
        ephemeral.exchange(recipient)
    )
    nonce = os.urandom(12)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    blob = (
        bytes([ECIES_VERSION])
        + ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        + nonce
        + sealed
    )
    return base64.b64encode(blob).decode()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("project_id")
    p.add_argument("profile")
    p.add_argument("owner")
    p.add_argument("secrets_json")
    p.add_argument("--access", default='"AllowAll"')
    p.add_argument("--api", default=os.environ.get("COORDINATOR_URL", "https://testnet-api.outlayer.ai"))
    p.add_argument("--network", default=os.environ.get("NETWORK", "testnet"))
    args = p.parse_args()

    json.loads(args.secrets_json)  # fail here rather than on chain
    key = pubkey_for(args.api, args.project_id, args.profile, args.owner, args.secrets_json)
    blob = envelope(key, args.secrets_json.encode())
    call = json.dumps({
        "accessor": {"Project": {"project_id": args.project_id}},
        "profile": args.profile,
        "encrypted_secrets_base64": blob,
        "access": json.loads(args.access),
    })
    print(
        "near contract call-function as-transaction outlayer.testnet store_secrets "
        f"json-args '{call}' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' "
        f"sign-as {args.owner} network-config {args.network} sign-with-legacy-keychain send"
    )


if __name__ == "__main__":
    main()
