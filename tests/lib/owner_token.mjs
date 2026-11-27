#!/usr/bin/env node
// The owner's `Bearer near:` token for one of their wallets, in the owner's scope.
//
//   OWNER_KEY_FILE=<near-cli credentials JSON> node owner_token.mjs <owner-account> <wallet-seed>
//
// Prints the token (without the `Bearer near:` prefix) and nothing else. It is
// good for 30 seconds: make one per request. The owner runs this on their own
// machine; the key file holds the owner account's full-access key (near-cli's
// `~/.near-credentials/<network>/<account>.json`: `public_key`, `private_key`),
// and neither the key nor the token is ever given to the agent.
//
// The signed message is `auth:<seed>:<timestamp>:@owner`, signed as it is
// (not NEP-413), which is why a browser wallet cannot make it. The same code is
// in the agent-custody skill (on-chain-custody.md, "On a new machine").
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [account, seed] = process.argv.slice(2);
if (!account || seed === undefined || !process.env.OWNER_KEY_FILE) {
  console.error('usage: OWNER_KEY_FILE=<credentials.json> node owner_token.mjs <owner-account> <wallet-seed>');
  process.exit(2);
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const fromB58 = (text) => {
  let n = 0n;
  for (const c of text) n = n * 58n + BigInt(B58.indexOf(c));
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.concat([Buffer.alloc(text.match(/^1*/)[0].length), Buffer.from(n ? hex : '', 'hex')]);
};
const toB58 = (bytes) => {
  let n = BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = `1${out}`;
  }
  return out;
};
const { public_key: pubkey, private_key: privateKey } = JSON.parse(readFileSync(process.env.OWNER_KEY_FILE, 'utf8'));
const seed32 = fromB58(privateKey.replace(/^ed25519:/, '')).subarray(0, 32);
const key = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed32]),
  format: 'der',
  type: 'pkcs8',
});
const timestamp = Math.floor(Date.now() / 1000);
const signature = toB58(sign(null, Buffer.from(`auth:${seed}:${timestamp}:@owner`), key));
const token = { account_id: account, seed, pubkey, timestamp, signature, master: 'owner' };
console.log(Buffer.from(JSON.stringify(token)).toString('base64url'));
