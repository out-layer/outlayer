#!/usr/bin/env node
// A raw ed25519 signature over a message's UTF-8 bytes, base58 with no prefix —
// the form `POST /register` and `Bearer near:` take (not NEP-413).
// Usage: CUSTOMER_RECOVERY_PRIVATE_KEY=ed25519:<base58 seed||pub> node ed25519_sign.mjs <message>
import { createPrivateKey, sign } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
  return out;
}
function unbase58(s) {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error('not base58'); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const lead = s.match(/^1*/)[0].length;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(n === 0n ? '' : hex, 'hex')]);
}

const secret = process.env.CUSTOMER_RECOVERY_PRIVATE_KEY ?? '';
const message = process.argv[2];
if (!secret.startsWith('ed25519:') || message === undefined) {
  console.error('usage: CUSTOMER_RECOVERY_PRIVATE_KEY=ed25519:… ed25519_sign.mjs <message>');
  process.exit(2);
}
const raw = unbase58(secret.slice('ed25519:'.length));
const key = createPrivateKey({
  key: { kty: 'OKP', crv: 'Ed25519', d: raw.subarray(0, 32).toString('base64url'), x: raw.subarray(32, 64).toString('base64url') },
  format: 'jwk',
});
process.stdout.write(base58(sign(null, Buffer.from(message, 'utf8'), key)));
