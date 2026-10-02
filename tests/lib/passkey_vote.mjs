#!/usr/bin/env node
// A NEP-641 passkey-wallet authorization for any payload — the blob a passkey
// approver's app sends as `authorization` in a contract vote.
//
// A port of HoS's `passkey-vote.ts` (`.idea/_todo/contract-wallet-vote-examples-hos.txt`,
// Appendix A) onto `node:crypto`, so the suites need no npm install. Same bytes:
// the message hash is SHA3-256("NEAR_NEP641_OFFCHAIN_MESSAGE/V1" || borsh(msg)),
// the WebAuthn challenge is its base64url, and the assertion is a low-S P-256
// signature over authenticator_data || SHA-256(client_data_json).
//
// Usage:
//   node tests/lib/passkey_vote.mjs <payload> <signer_id> <chain_id> [secret-byte] [offset-seconds]
//
// The secret is 32 copies of <secret-byte> (default 7: HoS's throwaway test key,
// which owns their test wallets — a public vector, never a funded key).
// <offset-seconds> shifts the message timestamp (default -60, as their script
// does; a positive offset makes a message "from the future").

import { createECDH, createHash, createPrivateKey, sign } from 'node:crypto';

const DOMAIN = 'NEAR_NEP641_OFFCHAIN_MESSAGE/V1';
const AUTHENTICATOR_DATA = Buffer.from('SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA', 'base64url');
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
const borshString = (s) => { const b = Buffer.from(s, 'utf8'); return Buffer.concat([u32le(b.length), b]); };

function base58(bytes) {
  let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
  return out;
}

export function messageHash(msg) {
  const path = msg.path ?? [];
  const nanos = BigInt(Date.parse(msg.timestamp)) * 1_000_000n;
  return createHash('sha3-256')
    .update(Buffer.concat([
      Buffer.from(DOMAIN, 'utf8'),
      borshString(msg.chain_id),
      borshString(msg.signer_id),
      u32le(path.length),
      ...path.map(borshString),
      u64le(nanos),
      borshString(msg.payload),
    ]))
    .digest();
}

function p256Key(secret) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(secret);
  const pub = ecdh.getPublicKey(); // 04 || x || y
  return createPrivateKey({
    key: {
      kty: 'EC', crv: 'P-256',
      d: secret.toString('base64url'),
      x: pub.subarray(1, 33).toString('base64url'),
      y: pub.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });
}

export function buildPasskeyAuthorization({ payload, secret, signerId, chainId, offsetSeconds = -60 }) {
  const seconds = Math.floor((Date.now() + offsetSeconds * 1000) / 1000);
  const timestamp = new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
  const msg = { chain_id: chainId, signer_id: signerId, timestamp, payload };
  const clientDataJson = JSON.stringify({
    type: 'webauthn.get',
    challenge: messageHash(msg).toString('base64url'),
    origin: 'http://localhost',
  });
  const signed = Buffer.concat([AUTHENTICATOR_DATA, createHash('sha256').update(clientDataJson, 'utf8').digest()]);
  const rs = sign('sha256', signed, { key: p256Key(secret), dsaEncoding: 'ieee-p1363' });
  // Low-S, as the wallet's verifier (and HoS's script) expects.
  let s = BigInt('0x' + rs.subarray(32).toString('hex'));
  if (s > P256_N / 2n) s = P256_N - s;
  const sig = Buffer.concat([rs.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]);
  const proof = JSON.stringify({
    authenticator_data: AUTHENTICATOR_DATA.toString('base64url'),
    client_data_json: clientDataJson,
    signature: `p256:${base58(sig)}`,
  });
  return JSON.stringify({ signature: { msg, proof } });
}

if (process.argv[1]?.endsWith('passkey_vote.mjs')) {
  const [payload, signerId, chainId, secretByte = '7', offset = '-60'] = process.argv.slice(2);
  if (!payload || !signerId || !chainId) {
    console.error('usage: passkey_vote.mjs <payload> <signer_id> <chain_id> [secret-byte] [offset-seconds]');
    process.exit(2);
  }
  const secret = Buffer.alloc(32, Number(secretByte));
  process.stdout.write(buildPasskeyAuthorization({ payload, secret, signerId, chainId, offsetSeconds: Number(offset) }));
}
