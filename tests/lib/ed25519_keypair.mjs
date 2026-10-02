#!/usr/bin/env node
// A fresh ed25519 keypair in NEAR's encoding, as JSON:
//   {"public_key": "ed25519:<base58 32>", "private_key": "ed25519:<base58 seed||pub>"}
// For suites that add a throwaway key to a test account and remove it after.
import { generateKeyPairSync } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
  return out;
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
const seed = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
process.stdout.write(JSON.stringify({
  public_key: `ed25519:${base58(pub)}`,
  private_key: `ed25519:${base58(Buffer.concat([seed, pub]))}`,
}));
