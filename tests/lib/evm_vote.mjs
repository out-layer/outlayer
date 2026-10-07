#!/usr/bin/env node
// An EIP-712 wallet authorization for any payload — the blob an EVM approver's
// app sends as `authorization` in a contract vote.
//
// A port of HoS's `evm-vote.ts` (`.idea/_todo/contract-wallet-vote-examples-hos.txt`,
// Appendix B) onto `node:crypto` plus in-file Keccak-256 and secp256k1, so the
// suites need no npm install. Same bytes: the digest is EIP-712 over domain
// {name: "NEAR Wallet Contract", version: "1"} and
// Authorization(string purpose,string recipient,string payload); the signature
// is RFC 6979 deterministic, low-S, packed r || s || v with v in {0, 1}, then
// base58 behind `secp256k1:`.
//
// Usage:
//   node tests/lib/evm_vote.mjs <payload> <recipient> [secret-byte]
//
// The secret is 32 copies of <secret-byte> (default 7: HoS's throwaway test key,
// which owns their test wallets — a public vector, never a funded key).

import { createHmac } from 'node:crypto';

const PURPOSE = 'PROVE_OWNERSHIP';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// ── Keccak-256 (the pre-NIST padding Ethereum uses; node's sha3-256 is not it) ──
const MASK = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const rotl = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK);

function keccakF(a) {
  for (let round = 0; round < 24; round++) {
    const c = [0, 1, 2, 3, 4].map((x) => a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) a[x + y] ^= d;
    }
    const b = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 25; y += 5) a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & MASK & b[(x + 2) % 5 + y]);
    a[0] ^= RC[round];
  }
}

export function keccak256(data) {
  const rate = 136;
  const msg = Buffer.from(data);
  const padded = Buffer.alloc(Math.ceil((msg.length + 1) / rate) * rate);
  msg.copy(padded);
  padded[msg.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const a = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) a[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(a);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(a[i], i * 8);
  return out;
}

// ── secp256k1 ───────────────────────────────────────────────────────────────
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0, m);
}
function add(p, q) {
  if (!p) return q;
  if (!q) return p;
  if (p[0] === q[0] && mod(p[1] + q[1]) === 0n) return null;
  const l = p[0] === q[0] ? mod(3n * p[0] * p[0] * inv(2n * p[1])) : mod((q[1] - p[1]) * inv(q[0] - p[0]));
  const x = mod(l * l - p[0] - q[0]);
  return [x, mod(l * (p[0] - x) - p[1])];
}
function mul(k, p = G) {
  let r = null;
  for (; k > 0n; k >>= 1n, p = add(p, p)) if (k & 1n) r = add(r, p);
  return r;
}
const big = (buf) => BigInt('0x' + Buffer.from(buf).toString('hex'));
const be32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');

// RFC 6979 nonce for a 32-byte digest, HMAC-SHA256.
function nonce(secret, digest) {
  const hmac = (key, ...parts) => createHmac('sha256', key).update(Buffer.concat(parts)).digest();
  const x = be32(big(secret));
  const h = be32(mod(big(digest), N));
  let v = Buffer.alloc(32, 1);
  let k = Buffer.alloc(32, 0);
  k = hmac(k, v, Buffer.of(0), x, h); v = hmac(k, v);
  k = hmac(k, v, Buffer.of(1), x, h); v = hmac(k, v);
  for (;;) {
    v = hmac(k, v);
    const t = big(v);
    if (t > 0n && t < N) return t;
    k = hmac(k, v, Buffer.of(0)); v = hmac(k, v);
  }
}

function signRecoverable(digest, secret) {
  const d = big(secret);
  const z = mod(big(digest), N);
  const k = nonce(secret, digest);
  const R = mul(k);
  const r = mod(R[0], N);
  let s = mod(inv(k, N) * (z + r * d), N);
  let v = Number(R[1] & 1n);
  if (s > N / 2n) { s = N - s; v ^= 1; }
  return Buffer.concat([be32(r), be32(s), Buffer.of(v)]);
}

function base58(bytes) {
  let n = big(bytes);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
  return out;
}

// ── EIP-712 ─────────────────────────────────────────────────────────────────
const k = (s) => keccak256(Buffer.from(s, 'utf8'));

export function authorizationDigest(payload, recipient) {
  const domain = keccak256(Buffer.concat([
    k('EIP712Domain(string name,string version)'), k('NEAR Wallet Contract'), k('1'),
  ]));
  const struct = keccak256(Buffer.concat([
    k('Authorization(string purpose,string recipient,string payload)'), k(PURPOSE), k(recipient), k(payload),
  ]));
  return keccak256(Buffer.concat([Buffer.of(0x19, 0x01), domain, struct]));
}

export function buildEvmAuthorization({ payload, recipient, secret }) {
  const signature = signRecoverable(authorizationDigest(payload, recipient), secret);
  return JSON.stringify({ purpose: PURPOSE, recipient, payload, signature: `secp256k1:${base58(signature)}` });
}

if (process.argv[1]?.endsWith('evm_vote.mjs')) {
  const [payload, recipient, secretByte = '7'] = process.argv.slice(2);
  if (!payload || !recipient) {
    console.error('usage: evm_vote.mjs <payload> <recipient> [secret-byte]');
    process.exit(2);
  }
  process.stdout.write(buildEvmAuthorization({ payload, recipient, secret: Buffer.alloc(32, Number(secretByte)) }));
}
