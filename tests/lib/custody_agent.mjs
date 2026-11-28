#!/usr/bin/env node
// The agent's side of on-chain custody for the live suites, with node:crypto only: the agent
// key from the owner's NEP-413 signature, the signed HTTPS request, the agent's half over a
// wallet contract request, the check of the TEE's half, the sealed owner's signature, and the
// arguments of `w_execute_signed`. The byte formats are custody-core's; `selftest` holds this
// file to custody-core's published vectors.
//
// Secrets never go on a command line: the agent's seed comes in AGENT_SEED_FILE (a file with
// 64 hex characters), and a private X25519 key lives in a file this script writes (0600).
//
//   selftest <vectors-dir>                       custody-core/vectors: messages, agent_request, keys
//   seed <owner> <wallet-id> <out>               the agent's seed from the owner's signature (base64,
//                                                in AGENT_KEY_SIGNATURE) → file
//   pub                                          the agent's public key, hex
//   headers <account> <METHOD> <path> <body-file>  curl header lines of a signed request
//   hash <msg.json>                              the request's hash, hex
//   half <msg.json>                              the agent's half over the request, hex
//   https-half <account> <METHOD> <path> <body-file>  an HTTPS request signature, hex (a refusal row)
//   verify-tee <msg.json> <tee-half-hex> <tee-pub-hex>  exit 0 when the TEE's half is valid
//   execute-args <msg.json> <proof-hex>          the JSON arguments of w_execute_signed
//   x25519-new <private-key-file>                a one-time key; prints its public key, hex
//   seal <recipient-pub-hex> <owner> <wallet-id> <signer-public-key>
//                                                the owner's page: the owner's NEP-413 signature (base64,
//                                                in AGENT_KEY_SIGNATURE) of the agent key's message,
//                                                verified first, sealed with the key that made it
//                                                (ed25519:…) to the agent's one-time key; base64
//   collect <private-key-file> <owner> <dao> <out>  the agent's collect, as the SDK's collectSetup: on
//                                                stdin {"setup": GET contract/setup, "key": GET
//                                                contract/key}; opens the seal, verifies the NEP-413
//                                                signature, reads on chain that its key is a full-access
//                                                key of <owner>, derives the seed, holds it to the
//                                                setup's agent_public_key, checks the keystore's
//                                                statement of the TEE key on <dao>, takes the account
//                                                only as the 0s address of the pair, <owner> or an
//                                                account under <owner>, and reads the pair on chain
//                                                (A‖E); the seed → <out>, prints the account; RPC_URL
//                                                (env)
//   deterministic <pair-hex>                     the 0s address (NEP-616) of a fresh wallet contract
//   create-0s <owner> <pair-hex>                 with the one-time key in PAGE_KEY_FILE (ed25519:…,
//                                                funded): StateInit at the 0s address, then the key's
//                                                account deleted to <owner>; RPC_URL (env)
//   tee-statement <dao> <owner> <wallet-id>      the owner's page's check of the TEE key: the JSON
//                                                answer on stdin (setup/owner or contract/key); the
//                                                keystore's signature over its statement, the scope
//                                                and wallet, then is_keystore_approved on <dao>;
//                                                prints the TEE key, hex; RPC_URL (env)
import {
  createHash, createHmac, createPrivateKey, createPublicKey, sign, verify,
  generateKeyPairSync, diffieHellman, hkdfSync, createCipheriv, createDecipheriv, randomBytes,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const utf8 = (s) => Buffer.from(s, 'utf8');
const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (s, n) => {
  if (typeof s !== 'string' || !/^[0-9a-f]*$/.test(s) || (n !== undefined && s.length !== 2 * n)) {
    throw new Error(`expected ${n ?? 'some'} bytes in lowercase hex`);
  }
  return Buffer.from(s, 'hex');
};
const le = (value, bytes) => {
  const out = Buffer.alloc(bytes);
  let v = BigInt(value);
  for (let i = 0; i < bytes; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  if (v !== 0n) throw new Error(`${value} does not fit in ${bytes} bytes`);
  return out;
};
const borshBytes = (b) => Buffer.concat([le(b.length, 4), Buffer.from(b)]);
const borshString = (s) => borshBytes(utf8(s));
const sha256 = (b) => createHash('sha256').update(b).digest();
const sha3 = (b) => createHash('sha3-256').update(b).digest();

const TIMEOUT_SECS = 600;
const REQUEST_DOMAIN = utf8('NEAR_WALLET_CONTRACT/V1');
const AGENT_PREFIX = utf8('NEAR_WALLET_TWO_KEY/V1/AGENT');
const TEE_PREFIX = utf8('NEAR_WALLET_TWO_KEY/V1/TEE');
const AGENT_REQUEST_DOMAIN = utf8('OUTLAYER_AGENT_REQUEST/V1');
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');
// The first byte of a sealed owner's signature; a seal of anything else (a seed) is refused.
const SEALED_FORMAT = 0x03;
const SEALED_LENGTH = 1 + 32 + 64 + 32 + 16;
const AGENT_KEY_RECIPIENT = 'outlayer-agent-key';
const AGENT_KEY_NONCE = Buffer.concat([utf8('outlayer/agent-key/v1/nonce'), Buffer.alloc(5)]);
const NEP413_TAG = 2 ** 31 + 413;
const NEP413_VECTOR = join(dirname(fileURLToPath(import.meta.url)), 'custody_nep413_vector.json');
const SEAL_KDF_INFO = utf8('outlayer:encryption-keys:v1:seal:kdf');

// ── keys ─────────────────────────────────────────────────────────────────────
const edPrivate = (seed) => createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
const edPublicOf = (seed) => createPublicKey(edPrivate(seed)).export({ format: 'der', type: 'spki' }).subarray(-32);
const edSign = (seed, bytes) => sign(null, bytes, edPrivate(seed));
const edVerify = (pub, bytes, sig) =>
  verify(null, bytes, createPublicKey({ key: Buffer.concat([SPKI_ED25519, pub]), format: 'der', type: 'spki' }), sig);

function agentSeed() {
  const file = process.env.AGENT_SEED_FILE;
  if (!file) throw new Error('AGENT_SEED_FILE is not set');
  return fromHex(readFileSync(file, 'utf8').trim(), 32);
}

const agentKeyMessage = (owner, walletId) =>
  `This signature is the key of your OutLayer agent. Sign it only on app.outlayer.ai, when you set up or recover an agent.\nOwner: ${owner}\nWallet: ${walletId}`;
// NEP-413, byte for byte the coordinator's verify_nep413_signature: SHA-256 of the tag (u32 LE)
// and borsh {message, nonce [32], recipient, callbackUrl: None}, signed with Ed25519.
const nep413Hash = (message, recipient, nonce) =>
  sha256(Buffer.concat([le(NEP413_TAG, 4), borshString(message), nonce, borshString(recipient), Buffer.of(0)]));
const agentKeySigned = (owner, walletId, signerPublic, signature) =>
  signerPublic.length === 32 && signature.length === 64
  && edVerify(signerPublic, nep413Hash(agentKeyMessage(owner, walletId), AGENT_KEY_RECIPIENT, AGENT_KEY_NONCE), signature);
function seedFromSignature(signature, owner, walletId) {
  if (signature.length !== 64) throw new Error('an Ed25519 signature is 64 bytes');
  return createHmac('sha256', utf8('outlayer/agent-key/v1'))
    .update(Buffer.concat([signature, utf8(agentKeyMessage(owner, walletId))])).digest();
}

// ── the wallet contract's request ────────────────────────────────────────────
function u(text, bits, name) {
  if (!/^(0|[1-9][0-9]*)$/.test(String(text))) throw new Error(`\`${name}\` is not a decimal number`);
  const v = BigInt(text);
  if (v >= 1n << BigInt(bits)) throw new Error(`\`${name}\` is out of range`);
  return v;
}
function borshOf(msg) {
  const a = msg.promise.action;
  const action = a.action === 'function_call'
    ? Buffer.concat([Buffer.of(2), borshString(a.function_name), borshBytes(Buffer.from(a.args, 'base64')),
        le(u(a.deposit, 128, 'deposit'), 16), le(u(a.gas, 64, 'gas'), 8), le(0n, 8)])
    : a.action === 'transfer'
      ? Buffer.concat([Buffer.of(3), le(u(a.amount, 128, 'amount'), 16)])
      : (() => { throw new Error(`unknown action ${a.action}`); })();
  if (!Number.isInteger(msg.nonce) || msg.nonce < 0 || msg.nonce > 0xffffffff) throw new Error('`nonce` is not a 32-bit number');
  return Buffer.concat([
    Buffer.of(0), borshString(msg.chain_id), borshString(msg.signer_id), le(msg.nonce, 4),
    le(u(msg.created_at_ns, 64, 'created_at_ns'), 8), le(TIMEOUT_SECS, 4), le(0, 4), le(1, 4),
    borshString(msg.promise.receiver_id), Buffer.of(0), le(1, 4), action,
  ]);
}
const requestHash = (msg) => sha3(Buffer.concat([REQUEST_DOMAIN, borshOf(msg)]));

function rfc3339(ns) {
  const n = BigInt(ns);
  const secs = n / 1_000_000_000n, frac = n % 1_000_000_000n;
  const day = new Date(Number(secs) * 1000).toISOString().slice(0, 19);
  return `${day}.${frac.toString().padStart(9, '0')}Z`;
}
// JSON.stringify writes every control character as custody-core does except that it uses the
// short escapes (\n, \t, …); custody-core writes \u00XX for all of them.
const jsonString = (s) => '"' + [...s].map((c) => c === '"' ? '\\"' : c === '\\' ? '\\\\'
  : c.codePointAt(0) < 0x20 ? `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}` : c).join('') + '"';
function contractJson(msg) {
  const a = msg.promise.action;
  const action = a.action === 'function_call'
    ? `{"action":"function_call","payload":{"function_name":${jsonString(a.function_name)},"args":"${a.args}","deposit":"${u(a.deposit, 128, 'deposit')}","gas":"${u(a.gas, 64, 'gas')}","gas_weight":"0"}}`
    : `{"action":"transfer","payload":{"amount":"${u(a.amount, 128, 'amount')}"}}`;
  return `{"chain_id":${jsonString(msg.chain_id)},"signer_id":${jsonString(msg.signer_id)},"nonce":${msg.nonce},"created_at":"${rfc3339(msg.created_at_ns)}","timeout_secs":${TIMEOUT_SECS},"request":{"external":[{"receiver_id":${jsonString(msg.promise.receiver_id)},"actions":[${action}]}]}}`;
}

// ── a signed HTTPS request ───────────────────────────────────────────────────
function requestBytes({ account, method, path, body, timestamp, nonce }) {
  if (nonce.length !== 16) throw new Error('a request nonce is 16 bytes');
  return Buffer.concat([AGENT_REQUEST_DOMAIN, borshString(account), borshString(method), borshString(path),
    sha256(utf8(body)), le(timestamp, 8), nonce]);
}

// ── the sealed owner's signature ─────────────────────────────────────────────
const xPrivate = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8_X25519, raw]), format: 'der', type: 'pkcs8' });
const xPublic = (raw) => createPublicKey({ key: Buffer.concat([SPKI_X25519, raw]), format: 'der', type: 'spki' });
const xRawPublic = (key) => createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
const aad = (walletId) => utf8(`outlayer:wallet-contract:agent-key:${walletId}`);
const sealKey = (shared, ephemeralPublic, recipientPublic) =>
  Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([SEAL_KDF_INFO, ephemeralPublic, recipientPublic]), 32));
function seal(recipientPublic, plaintext, walletId, format = SEALED_FORMAT) {
  const eph = generateKeyPairSync('x25519');
  const ephPublic = xRawPublic(eph.privateKey);
  const key = sealKey(diffieHellman({ privateKey: eph.privateKey, publicKey: xPublic(recipientPublic) }), ephPublic, recipientPublic);
  const c = createCipheriv('aes-256-gcm', key, Buffer.alloc(12)); c.setAAD(aad(walletId));
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return Buffer.concat([Buffer.of(format), ephPublic, ct]);
}
/** The owner's signature and its public key, opened; nothing of them is checked here. */
function open(privateRaw, sealed, walletId) {
  if (sealed[0] !== SEALED_FORMAT || sealed.length !== SEALED_LENGTH) throw new Error("this is not a sealed owner's signature");
  const priv = xPrivate(privateRaw);
  const ephPublic = sealed.subarray(1, 33);
  const key = sealKey(diffieHellman({ privateKey: priv, publicKey: xPublic(ephPublic) }), ephPublic, xRawPublic(priv));
  const d = createDecipheriv('aes-256-gcm', key, Buffer.alloc(12)); d.setAAD(aad(walletId));
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  const opened = Buffer.concat([d.update(sealed.subarray(33, sealed.length - 16)), d.final()]);
  return { signature: opened.subarray(0, 64), publicKey: opened.subarray(64) };
}

// ── a wallet contract at its deterministic address (NEP-616) ───────────────────
// keccak-256 (not SHA3: the original padding), for "0s" + hex(keccak256(borsh(StateInit))[12..32]).
const KECCAK_RC = [
  0x1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n,
  0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an,
  0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n,
];
const KECCAK_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const M64 = (1n << 64n) - 1n;
const rotl = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64);
function keccak256(data) {
  const rate = 136;
  const padded = Buffer.alloc(Math.ceil((data.length + 1) / rate) * rate);
  Buffer.from(data).copy(padded);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const st = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) st[i] ^= padded.readBigUInt64LE(off + 8 * i);
    for (let round = 0; round < 24; round++) {
      const c = [0, 1, 2, 3, 4].map((x) => st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]);
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
        for (let y = 0; y < 25; y += 5) st[x + y] ^= d;
      }
      const b = new Array(25);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(st[x + 5 * y], KECCAK_ROT[x + 5 * y]);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & M64 & b[((x + 2) % 5) + 5 * y]);
      st[0] ^= KECCAK_RC[round];
    }
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(st[i], 8 * i);
  return out;
}

/** The published two-key build, by code hash (651XC7DH8J4Xczf8JKXH9pyveBY8ZuNCfy5HZ3SvuSiL). */
const WALLET_BUILD = Buffer.from('4b5158b0d1e911e86575ec7aa3cd07d5df23b5aa5572544aa981b5e154eb6771', 'hex');
const stateOf = (pair) => Buffer.concat([Buffer.of(1), le(0, 4), fromHex(pair, 64), le(3600, 4), le(0, 8), le(0, 4), le(0, 4), le(0, 4)]);
const stateInitOf = (pair, build = WALLET_BUILD) => {
  const state = stateOf(pair);
  return Buffer.concat([Buffer.of(0, 0), build, le(1, 4), le(0, 4), le(state.length, 4), state]);
};
const deterministic = (pair, build = WALLET_BUILD) => `0s${hex(keccak256(stateInitOf(pair, build)).subarray(12))}`;

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function unbase58(text) {
  let n = 0n;
  for (const c of text) { const i = B58.indexOf(c); if (i < 0) throw new Error('not base58'); n = n * 58n + BigInt(i); }
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  return Buffer.concat([Buffer.alloc(text.match(/^1*/)[0].length), Buffer.from(n === 0n ? '' : h, 'hex')]);
}
/** A signed transaction of one action, base64: the frame nearcore takes. */
function signedTx(seed, signerId, receiverId, nonce, blockHash, action) {
  const tx = Buffer.concat([borshString(signerId), Buffer.of(0), edPublicOf(seed), le(nonce, 8), borshString(receiverId), blockHash, le(1, 4), action]);
  return Buffer.concat([tx, Buffer.of(0), edSign(seed, sha256(tx))]).toString('base64');
}
async function rpcCall(method, params) {
  const r = await fetch(process.env.RPC_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body = await r.json();
  if (body.error) throw new Error(JSON.stringify(body.error.data ?? body.error).slice(0, 300));
  return body.result;
}
/** StateInit at the 0s address by the funded one-time key; the key's account is deleted to
 *  the owner whatever the StateInit did, as the page does. Both sent as the page sends them. */
async function create0s(owner, pair) {
  const secret = readFileSync(process.env.PAGE_KEY_FILE, 'utf8').trim();
  const seed = unbase58(secret.slice('ed25519:'.length)).subarray(0, 32);
  const signer = hex(edPublicOf(seed));
  const ak = await rpcCall('query', { request_type: 'view_access_key', finality: 'final', account_id: signer, public_key: `ed25519:${base58(edPublicOf(seed))}` });
  const nonce = BigInt(ak.nonce) + 1n, blockHash = unbase58(ak.block_hash);
  const account = deterministic(pair);
  const send = (receiver, n, action) => rpcCall('send_tx', { signed_tx_base64: signedTx(seed, signer, receiver, n, blockHash, action), wait_until: 'FINAL' });
  const failed = (o) => o.status && o.status.Failure ? JSON.stringify(o.status.Failure).slice(0, 200) : null;
  let why = null;
  try {
    const created = await send(account, nonce, Buffer.concat([Buffer.of(11), stateInitOf(pair), le(0, 16)]));
    if (failed(created)) why = `StateInit failed: ${failed(created)}`;
  } catch (e) {
    why = `StateInit was not sent: ${e.message}`;
  } finally {
    const closed = await send(signer, nonce + 1n, Buffer.concat([Buffer.of(7), borshString(owner)]));
    if (failed(closed)) why = `${why ? `${why}; ` : ''}the one-time key's account was not deleted: ${failed(closed)}`;
  }
  if (why) throw new Error(why);
  return account;
}
function base58(bytes) {
  let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0')); let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
  return out;
}

// ── the keystore's statement over the TEE key ────────────────────────────────
// The keystore's registration key (approved in the keystore DAO) signs this text; the owner's
// page and the agent's SDK check it before they use the TEE key the coordinator carried.
const TEE_KEY_STATEMENT_TAG = 'OUTLAYER_WALLET_CONTRACT_TEE_KEY/V1';
const TEE_KEY_VECTOR = join(dirname(fileURLToPath(import.meta.url)), '../../keystore-worker/src/fixtures/tee_key_statement_vector.json');
const teeKeyStatement = ({ dao, scope, wallet, tee }) =>
  [TEE_KEY_STATEMENT_TAG, `dao:${dao}`, `scope:${scope}`, `wallet:${wallet}`, `tee:${tee}`].join('\n');
/** The registration key of `ed25519:<base58>`, 32 bytes; any other scheme is refused. */
function registrationKey(text) {
  if (typeof text !== 'string' || !text.startsWith('ed25519:')) throw new Error('the keystore key is not an ed25519 key');
  const raw = unbase58(text.slice('ed25519:'.length));
  if (raw.length !== 32 || `ed25519:${base58(raw)}` !== text) throw new Error('the keystore key is not 32 bytes in base58');
  return raw;
}
/** The checks of the answer itself, without the chain: its fields, the scope of `owner`, the
 *  wallet, and the signature over the statement. Returns the registration key's text. */
function checkTeeStatement(answer, dao, owner, walletId) {
  const { tee_public_key: tee, scope, keystore_public_key: keystore, tee_key_signature: signature } = answer ?? {};
  fromHex(tee, 32);
  const sig = fromHex(signature, 64);
  const ownerScope = new RegExp(`^owner:${owner.replace(/[.]/g, '\\.')}:[1-9][0-9]*$`);
  if (typeof scope !== 'string' || !ownerScope.test(scope)) throw new Error(`the statement's scope is not ${owner}'s`);
  const statement = teeKeyStatement({ dao, scope, wallet: walletId, tee });
  if (!edVerify(registrationKey(keystore), utf8(statement), sig)) {
    throw new Error('the keystore\'s signature does not verify over the statement of this TEE key, owner, wallet and DAO');
  }
  return keystore;
}
async function isKeystoreApproved(dao, publicKey) {
  const answer = await rpcCall('query', {
    request_type: 'call_function', finality: 'final', account_id: dao, method_name: 'is_keystore_approved',
    args_base64: Buffer.from(JSON.stringify({ public_key: publicKey })).toString('base64'),
  });
  return JSON.parse(Buffer.from(answer.result).toString('utf8')) === true;
}
async function teeStatement(dao, owner, walletId, text) {
  const answer = JSON.parse(text);
  const keystore = checkTeeStatement(answer, dao, owner, walletId);
  if (!(await isKeystoreApproved(dao, keystore))) throw new Error(`${dao} does not approve the keystore key that signed the statement`);
  return answer.tee_public_key;
}

// ── the agent's collect ──────────────────────────────────────────────────────
// Whoever knows the agent's one-time public key (the coordinator does) can seal to it, so the
// agent takes nothing of the seal on its word: the signature has to be the owner's, over the
// message the agent builds, and the account has to hold the pair on chain. `chain` reads
// through the RPC: { fullAccess(account, publicKeyText), pairOf(account), approved(dao, key) }.
async function collectChecks({ setup, key }, privateRaw, owner, dao, chain) {
  const walletId = String(setup?.wallet_id);
  if (setup?.done !== true) throw new Error('the setup is not finished');
  const { signature, publicKey } = open(privateRaw, Buffer.from(String(setup.sealed_agent_key), 'base64'), walletId);
  if (!agentKeySigned(owner, walletId, publicKey, signature)) {
    throw new Error(`the sealed signature is not a NEP-413 signature of the agent key's message for ${owner}'s wallet ${walletId}`);
  }
  const signer = `ed25519:${base58(publicKey)}`;
  if (!(await chain.fullAccess(owner, signer))) throw new Error(`${signer} is not a full-access key of ${owner}`);
  const seed = seedFromSignature(signature, owner, walletId);
  const agent = hex(edPublicOf(seed));
  if (agent !== setup.agent_public_key) throw new Error("the key the owner's signature makes is not the agent key the API recorded");
  const keystore = checkTeeStatement(key, dao, owner, walletId);
  if (!(await chain.approved(dao, keystore))) throw new Error(`${dao} does not approve the keystore key that signed the statement`);
  const pair = agent + key.tee_public_key;
  // The account is one this owner's setup can make: the 0s address of the pair, the owner's
  // account, or an account under it. Any other is refused whatever it answers on chain: anyone
  // can deploy a contract whose `w_public_key` returns this pair.
  const account = String(setup.account_id);
  if (/^0s[0-9a-f]{40}$/.test(account)) {
    if (account !== deterministic(pair)) throw new Error(`${account} is not the 0s address of the pair`);
  } else if (account !== owner && !account.endsWith(`.${owner}`)) {
    throw new Error(`${account} is not the 0s address of the pair, ${owner}, or an account under ${owner}`);
  }
  const onChain = await chain.pairOf(account);
  if (onChain !== pair) throw new Error(`${account} holds ${onChain === null ? 'no wallet contract' : 'another pair'} on chain, not the agent's key and this wallet's TEE key`);
  return { seed, account };
}
const rpcChain = {
  async fullAccess(account, publicKey) {
    try {
      const k = await rpcCall('query', { request_type: 'view_access_key', finality: 'final', account_id: account, public_key: publicKey });
      return k.permission === 'FullAccess';
    } catch (e) {
      if (/UNKNOWN_ACCESS_KEY|UNKNOWN_ACCOUNT/.test(e.message)) return false;
      throw e;
    }
  },
  async pairOf(account) {
    try {
      const r = await rpcCall('query', { request_type: 'call_function', finality: 'final', account_id: account, method_name: 'w_public_key', args_base64: 'e30=' });
      if (!r.result) return null;
      const text = JSON.parse(Buffer.from(r.result).toString('utf8'));
      return typeof text === 'string' ? text : null;
    } catch (e) {
      if (/UNKNOWN_ACCOUNT|CodeDoesNotExist|MethodNotFound|NO_CONTRACT_CODE|MethodResolveError/.test(e.message)) return null;
      throw e;
    }
  },
  approved: isKeystoreApproved,
};

// ── selftest ─────────────────────────────────────────────────────────────────
async function selftest(dir) {
  let ok = 0;
  const same = (what, got, want) => {
    if (got !== want) throw new Error(`${what}: got ${String(got).slice(0, 80)}, want ${String(want).slice(0, 80)}`);
    ok++;
  };
  const m = JSON.parse(readFileSync(join(dir, 'messages.json'), 'utf8'));
  const aSeed = fromHex(m.agent_seed, 32), tSeed = fromHex(m.tee_seed, 32);
  same('the pair', hex(edPublicOf(aSeed)) + hex(edPublicOf(tSeed)), m.public_key);
  for (const c of m.cases) {
    same(`${c.name}: borsh`, hex(borshOf(c.message)), c.borsh);
    same(`${c.name}: hash`, hex(requestHash(c.message)), c.hash);
    same(`${c.name}: contract json`, contractJson(c.message), c.contract_json);
    same(`${c.name}: agent half`, hex(edSign(aSeed, Buffer.concat([AGENT_PREFIX, requestHash(c.message)]))), c.agent_half);
    same(`${c.name}: tee half verifies`, edVerify(edPublicOf(tSeed), Buffer.concat([TEE_PREFIX, requestHash(c.message)]), fromHex(c.tee_half, 64)), true);
  }
  const r = JSON.parse(readFileSync(join(dir, 'agent_request.json'), 'utf8'));
  const rSeed = fromHex(r.agent_seed, 32);
  same('request key', hex(edPublicOf(rSeed)), r.agent_public_key);
  for (const c of r.cases) {
    const bytes = requestBytes({ account: c.wallet_contract, method: c.method, path: c.path, body: c.body, timestamp: c.timestamp, nonce: fromHex(c.nonce, 16) });
    same(`request ${c.path}: bytes`, hex(bytes), c.signed_bytes);
    same(`request ${c.path}: signature`, hex(edSign(rSeed, bytes)), c.signature);
  }
  const k = JSON.parse(readFileSync(join(dir, 'keys.json'), 'utf8'));
  same('agent key message', agentKeyMessage(k.owner, k.wallet_id), k.agent.nep413_message);
  const seed = seedFromSignature(fromHex(k.agent.signature, 64), k.owner, k.wallet_id);
  same('agent seed', hex(seed), k.agent.seed);
  same('agent public key', hex(edPublicOf(seed)), k.agent.public_key);
  if (existsSync(join(dir, 'deterministic.json'))) {
    const d = JSON.parse(readFileSync(join(dir, 'deterministic.json'), 'utf8'));
    const build = Buffer.from(d.code_hash_hex, 'hex');
    same('the published build', d.code_hash_hex, hex(WALLET_BUILD));
    for (const c of d.cases) {
      same(`${c.name}: 0s state`, hex(stateOf(c.pair)), c.state);
      same(`${c.name}: 0s state_init`, hex(stateInitOf(c.pair, build)), c.state_init);
      same(`${c.name}: 0s address`, deterministic(c.pair, build), c.account_id);
    }
  }
  const v = JSON.parse(readFileSync(TEE_KEY_VECTOR, 'utf8'));
  same('the tee key statement', teeKeyStatement(v), v.statement);
  same('the vector key', `ed25519:${base58(edPublicOf(fromHex(v.secret_seed, 32)))}`, v.public_key);
  same('the vector signature', hex(edSign(fromHex(v.secret_seed, 32), utf8(v.statement))), v.signature);
  const stated = { tee_public_key: v.tee, scope: v.scope, keystore_public_key: v.public_key, tee_key_signature: v.signature };
  const owner = v.scope.split(':')[1];
  same('the statement checks', checkTeeStatement(stated, v.dao, owner, v.wallet), v.public_key);
  const refused = (what, answer, dao = v.dao, who = owner, wallet = v.wallet) => {
    let threw = false;
    try { checkTeeStatement(answer, dao, who, wallet); } catch { threw = true; }
    same(`the statement is refused: ${what}`, threw, true);
  };
  refused('another TEE key', { ...stated, tee_public_key: 'ab'.repeat(32) });
  refused('another DAO', stated, 'dao.evil.testnet');
  refused('another owner', stated, v.dao, 'bob.testnet');
  refused('another wallet', stated, v.dao, owner, 'another-wallet');
  refused('another scope', { ...stated, scope: 'owner:bob.testnet:1' });
  refused('another signing key', { ...stated, keystore_public_key: `ed25519:${base58(edPublicOf(Buffer.alloc(32, 7)))}` });
  refused('an ml-dsa key', { ...stated, keystore_public_key: 'ml-dsa-65:' + v.public_key.slice(8) });
  refused('no signature', { ...stated, tee_key_signature: undefined });
  // NEP-413: the vector node:crypto made and the coordinator's verify_nep413_signature accepts
  const n = JSON.parse(readFileSync(NEP413_VECTOR, 'utf8'));
  const nSig = fromHex(n.signature_hex, 64), nKey = fromHex(n.owner_public_key_hex, 32);
  same('nep413 message', agentKeyMessage(n.owner, n.wallet_id), n.message);
  same('nep413 nonce', hex(AGENT_KEY_NONCE), n.nonce_hex);
  same('nep413 hash', hex(nep413Hash(n.message, n.recipient, AGENT_KEY_NONCE)), n.signed_hash_hex);
  same('nep413 key', `ed25519:${base58(nKey)}`, n.owner_public_key);
  same('nep413 signature verifies', agentKeySigned(n.owner, n.wallet_id, nKey, nSig), true);
  same('nep413 for another owner', agentKeySigned('bob.near', n.wallet_id, nKey, nSig), false);
  same('nep413 for another wallet', agentKeySigned(n.owner, 'another-wallet', nKey, nSig), false);
  same('nep413 seed', hex(seedFromSignature(nSig, n.owner, n.wallet_id)), n.agent_seed);
  same('nep413 the signature is what a key file signs', hex(edSign(fromHex(n.owner_secret_seed, 32), fromHex(n.signed_hash_hex, 32))), n.signature_hex);

  // the seal, and the agent's collect against a chain that answers as told
  const x = generateKeyPairSync('x25519');
  const xRaw = x.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  const xPub = xRawPublic(x.privateKey);
  const signedByOwner = Buffer.concat([nSig, nKey]);
  const opened = open(xRaw, seal(xPub, signedByOwner, n.wallet_id), n.wallet_id);
  same('seal and open', hex(opened.signature) + hex(opened.publicKey), hex(signedByOwner));
  const refusedAs = async (what, run, why) => {
    let said = null;
    try { await run(); } catch (e) { said = e.message; }
    same(`refused: ${what}`, said !== null && why.test(said), true);
  };
  await refusedAs('a seal for another wallet', () => open(xRaw, seal(xPub, signedByOwner, n.wallet_id), 'another-wallet'), /./);
  const tee = v.tee; // a TEE key with a statement of the vector's keystore, for alice.testnet
  const sOwner = v.scope.split(':')[1];
  const sSig = (seedHex, owner = sOwner, wallet = v.wallet) => {
    const signerSeed = fromHex(seedHex, 32);
    const signature = edSign(signerSeed, nep413Hash(agentKeyMessage(owner, wallet), AGENT_KEY_RECIPIENT, AGENT_KEY_NONCE));
    return Buffer.concat([signature, edPublicOf(signerSeed)]);
  };
  const OWNER_SEED = n.owner_secret_seed, OTHER_SEED = '11'.repeat(32);
  const ownerKeyText = `ed25519:${base58(edPublicOf(fromHex(OWNER_SEED, 32)))}`;
  const answerFor = (plaintext, { format, account = 'agent.alice.testnet', agent } = {}) => {
    const sig = plaintext.subarray(0, 64);
    return {
      setup: {
        wallet_id: v.wallet, done: true, account_id: account,
        agent_public_key: agent ?? (plaintext.length === 96 ? hex(edPublicOf(seedFromSignature(sig, sOwner, v.wallet))) : 'ab'.repeat(32)),
        sealed_agent_key: seal(xPub, plaintext, v.wallet, format).toString('base64'),
      },
      key: stated,
    };
  };
  const chainWith = (pairs) => ({
    fullAccess: async (account, publicKey) => account === sOwner && publicKey === ownerKeyText,
    pairOf: async (account) => pairs[account] ?? null,
    approved: async (dao, keystore) => dao === v.dao && keystore === v.public_key,
  });
  const good = sSig(OWNER_SEED);
  const goodAgent = hex(edPublicOf(seedFromSignature(good.subarray(0, 64), sOwner, v.wallet)));
  const chain = chainWith({ 'agent.alice.testnet': goodAgent + tee, [deterministic(goodAgent + tee)]: goodAgent + tee });
  const collected = await collectChecks(answerFor(good), xRaw, sOwner, v.dao, chain);
  same('collect: the seed of the owner\'s signature', hex(collected.seed), hex(seedFromSignature(good.subarray(0, 64), sOwner, v.wallet)));
  same('collect: a 0s account of the pair', (await collectChecks(answerFor(good, { account: deterministic(goodAgent + tee) }), xRaw, sOwner, v.dao, chain)).account, deterministic(goodAgent + tee));
  // the coordinator's own key signing the owner's message, with its own account holding its pair
  const forged = sSig(OTHER_SEED);
  const forgedAgent = hex(edPublicOf(seedFromSignature(forged.subarray(0, 64), sOwner, v.wallet)));
  const forgedChain = chainWith({ 'agent.alice.testnet': forgedAgent + tee });
  await refusedAs('a signature by a key that is not the owner\'s', () => collectChecks(answerFor(forged), xRaw, sOwner, v.dao, forgedChain), /not a full-access key of alice.testnet/);
  await refusedAs('the owner\'s key named beside another key\'s signature', () => collectChecks(answerFor(Buffer.concat([forged.subarray(0, 64), good.subarray(64)])), xRaw, sOwner, v.dao, chain), /not a NEP-413 signature/);
  await refusedAs('the owner\'s signature of another wallet\'s message', () => collectChecks(answerFor(sSig(OWNER_SEED, sOwner, 'another-wallet')), xRaw, sOwner, v.dao, chain), /not a NEP-413 signature/);
  await refusedAs('a random seed, sealed the earlier way (0x02)', () => collectChecks(answerFor(randomBytes(32), { format: 0x02 }), xRaw, sOwner, v.dao, chain), /not a sealed owner's signature/);
  await refusedAs('the signature under the earlier format byte', () => collectChecks(answerFor(good, { format: 0x02 }), xRaw, sOwner, v.dao, chain), /not a sealed owner's signature/);
  await refusedAs('another agent key on record', () => collectChecks(answerFor(good, { agent: forgedAgent }), xRaw, sOwner, v.dao, chain), /not the agent key the API recorded/);
  await refusedAs('an account without the pair on chain', () => collectChecks(answerFor(good, { account: 'other.alice.testnet' }), xRaw, sOwner, v.dao, chain), /no wallet contract on chain/);
  await refusedAs('an account with another pair on chain', () => collectChecks(answerFor(good), xRaw, sOwner, v.dao, chainWith({ 'agent.alice.testnet': goodAgent + 'cd'.repeat(32) })), /another pair on chain/);
  // the account: the owner's own and one under it at any depth are taken; any other is refused,
  // though it answers with the pair on chain
  const strangers = ['mallory.testnet', 'xalice.testnet', 'alice.testnet.mallory.testnet', '0sam.testnet', 'testnet', deterministic(tee + goodAgent), deterministic(goodAgent + tee).toUpperCase()];
  const anyChain = chainWith(Object.fromEntries(['alice.testnet', 'a.agent.alice.testnet', ...strangers].map((a) => [a, goodAgent + tee])));
  for (const account of ['alice.testnet', 'a.agent.alice.testnet']) {
    same(`collect: ${account}`, (await collectChecks(answerFor(good, { account }), xRaw, sOwner, v.dao, anyChain)).account, account);
  }
  for (const account of strangers) {
    await refusedAs(`the account ${account}, with the pair on chain`, () => collectChecks(answerFor(good, { account }), xRaw, sOwner, v.dao, anyChain), /is not the 0s address of the pair/);
  }
  await refusedAs('a keystore the DAO does not approve', () => collectChecks(answerFor(good), xRaw, sOwner, v.dao, { ...chain, approved: async () => false }), /does not approve/);
  await refusedAs('another owner', () => collectChecks(answerFor(good), xRaw, 'bob.testnet', v.dao, chain), /not a NEP-413 signature/);
  console.log(`selftest: ${ok} checks against ${dir}`);
}

// ── main ─────────────────────────────────────────────────────────────────────
const readMsg = (file) => JSON.parse(readFileSync(file, 'utf8'));
const writeSecret = (file, text) => writeFileSync(file, text, { mode: 0o600 });
const [cmd, ...args] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'selftest': await selftest(args[0]); break;
    case 'seed': {
      const [owner, walletId, out] = args;
      const sigB64 = process.env.AGENT_KEY_SIGNATURE;
      if (!sigB64) throw new Error('AGENT_KEY_SIGNATURE is not set');
      writeSecret(out, hex(seedFromSignature(Buffer.from(sigB64, 'base64'), owner, walletId)));
      break;
    }
    case 'pub': console.log(hex(edPublicOf(agentSeed()))); break;
    case 'headers':
    case 'https-half': {
      const [account, method, path, bodyFile] = args;
      const timestamp = Number(process.env.AGENT_TIMESTAMP ?? Math.floor(Date.now() / 1000));
      const nonce = process.env.AGENT_NONCE ? fromHex(process.env.AGENT_NONCE, 16) : randomBytes(16);
      const body = bodyFile ? readFileSync(bodyFile, 'utf8') : '';
      const signature = edSign(agentSeed(), requestBytes({ account, method, path, body, timestamp, nonce }));
      if (cmd === 'https-half') { console.log(hex(signature)); break; }
      console.log(`x-agent-account: ${account}\nx-agent-timestamp: ${timestamp}\nx-agent-nonce: ${hex(nonce)}\nx-agent-signature: ${hex(signature)}`);
      break;
    }
    case 'hash': console.log(hex(requestHash(readMsg(args[0])))); break;
    case 'half': console.log(hex(edSign(agentSeed(), Buffer.concat([AGENT_PREFIX, requestHash(readMsg(args[0]))])))); break;
    case 'verify-tee': {
      const [file, half, pub] = args;
      process.exit(edVerify(fromHex(pub, 32), Buffer.concat([TEE_PREFIX, requestHash(readMsg(file))]), fromHex(half, 64)) ? 0 : 1);
    }
    case 'execute-args': console.log(`{"msg":${contractJson(readMsg(args[0]))},"proof":${jsonString(args[1])}}`); break;
    case 'x25519-new': {
      const x = generateKeyPairSync('x25519');
      writeSecret(args[0], hex(x.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32)));
      console.log(hex(xRawPublic(x.privateKey)));
      break;
    }
    case 'seal': {
      const [recipient, owner, walletId, signerText] = args;
      const sigB64 = process.env.AGENT_KEY_SIGNATURE;
      if (!sigB64) throw new Error('AGENT_KEY_SIGNATURE is not set');
      const signature = Buffer.from(sigB64, 'base64');
      let signer;
      try { signer = registrationKey(signerText); } catch { throw new Error('the signer key is not ed25519:<base58> of 32 bytes'); }
      // as the page: a signature that is not standard NEP-413 of this message is never sent
      if (!agentKeySigned(owner, walletId, signer, signature)) throw new Error("the signature is not a NEP-413 signature of the agent key's message");
      console.log(seal(fromHex(recipient, 32), Buffer.concat([signature, signer]), walletId).toString('base64'));
      break;
    }
    case 'collect': {
      const [privFile, owner, dao, out] = args;
      const { seed, account } = await collectChecks(JSON.parse(readFileSync(0, 'utf8')), fromHex(readFileSync(privFile, 'utf8').trim(), 32), owner, dao, rpcChain);
      writeSecret(out, hex(seed));
      console.log(account);
      break;
    }
    case 'deterministic': console.log(deterministic(args[0])); break;
    case 'create-0s': console.log(await create0s(args[0], args[1])); break;
    case 'tee-statement': console.log(await teeStatement(args[0], args[1], args[2], readFileSync(0, 'utf8'))); break;
    default:
      console.error('usage: custody_agent.mjs selftest|seed|pub|headers|hash|half|https-half|verify-tee|execute-args|x25519-new|seal|collect|deterministic|create-0s|tee-statement …');
      process.exit(2);
  }
} catch (e) {
  console.error(`custody_agent: ${e.message}`);
  process.exit(1);
}
