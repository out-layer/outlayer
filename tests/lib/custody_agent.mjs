#!/usr/bin/env node
// The agent's side of on-chain custody for the live suites, with node:crypto only: the agent
// key from the owner's NEP-413 signature, the signed HTTPS request, the agent's half over a
// wallet contract request, the check of the TEE's half, the sealed agent key, and the
// arguments of `w_execute_signed`. The byte formats are custody-core's; `selftest` holds this
// file to custody-core's published vectors.
//
// Secrets never go on a command line: the agent's seed comes in AGENT_SEED_FILE (a file with
// 64 hex characters), and a private X25519 key lives in a file this script writes (0600).
//
//   selftest <vectors-dir>                       custody-core/vectors: messages, agent_request, keys
//   seed <owner> <wallet-id> <sig-base64> <out>  the agent's seed from the owner's signature → file
//   pub                                          the agent's public key, hex
//   headers <account> <METHOD> <path> <body-file>  curl header lines of a signed request
//   hash <msg.json>                              the request's hash, hex
//   half <msg.json>                              the agent's half over the request, hex
//   https-half <account> <METHOD> <path> <body-file>  an HTTPS request signature, hex (a refusal row)
//   verify-tee <msg.json> <tee-half-hex> <tee-pub-hex>  exit 0 when the TEE's half is valid
//   execute-args <msg.json> <proof-hex>          the JSON arguments of w_execute_signed
//   x25519-new <private-key-file>                a one-time key; prints its public key, hex
//   seal <recipient-pub-hex> <wallet-id>         the agent's seed sealed to it, base64
//   open <private-key-file> <wallet-id> <sealed-base64> <out>  the seed it opens → file
import {
  createHash, createHmac, createPrivateKey, createPublicKey, sign, verify,
  generateKeyPairSync, diffieHellman, hkdfSync, createCipheriv, createDecipheriv, randomBytes,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

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
const SEALED_FORMAT = 0x02;
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

// ── the sealed agent key ─────────────────────────────────────────────────────
const xPrivate = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8_X25519, raw]), format: 'der', type: 'pkcs8' });
const xPublic = (raw) => createPublicKey({ key: Buffer.concat([SPKI_X25519, raw]), format: 'der', type: 'spki' });
const xRawPublic = (key) => createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
const aad = (walletId) => utf8(`outlayer:wallet-contract:agent-key:${walletId}`);
const sealKey = (shared, ephemeralPublic, recipientPublic) =>
  Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([SEAL_KDF_INFO, ephemeralPublic, recipientPublic]), 32));
function seal(recipientPublic, seed, walletId) {
  const eph = generateKeyPairSync('x25519');
  const ephPublic = xRawPublic(eph.privateKey);
  const key = sealKey(diffieHellman({ privateKey: eph.privateKey, publicKey: xPublic(recipientPublic) }), ephPublic, recipientPublic);
  const c = createCipheriv('aes-256-gcm', key, Buffer.alloc(12)); c.setAAD(aad(walletId));
  const ct = Buffer.concat([c.update(seed), c.final(), c.getAuthTag()]);
  return Buffer.concat([Buffer.of(SEALED_FORMAT), ephPublic, ct]);
}
function open(privateRaw, sealed, walletId) {
  if (sealed[0] !== SEALED_FORMAT || sealed.length !== 1 + 32 + 32 + 16) throw new Error('this is not a sealed agent key');
  const priv = xPrivate(privateRaw);
  const ephPublic = sealed.subarray(1, 33);
  const key = sealKey(diffieHellman({ privateKey: priv, publicKey: xPublic(ephPublic) }), ephPublic, xRawPublic(priv));
  const d = createDecipheriv('aes-256-gcm', key, Buffer.alloc(12)); d.setAAD(aad(walletId));
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([d.update(sealed.subarray(33, sealed.length - 16)), d.final()]);
}

// ── selftest ─────────────────────────────────────────────────────────────────
function selftest(dir) {
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
  const x = generateKeyPairSync('x25519');
  const xRaw = x.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  same('seal and open', hex(open(xRaw, seal(xRawPublic(x.privateKey), seed, k.wallet_id), k.wallet_id)), hex(seed));
  let other = false;
  try { open(xRaw, seal(xRawPublic(x.privateKey), seed, k.wallet_id), 'another-wallet'); } catch { other = true; }
  same('a key sealed for another wallet does not open', other, true);
  console.log(`selftest: ${ok} checks against ${dir}`);
}

// ── main ─────────────────────────────────────────────────────────────────────
const readMsg = (file) => JSON.parse(readFileSync(file, 'utf8'));
const writeSecret = (file, text) => writeFileSync(file, text, { mode: 0o600 });
const [cmd, ...args] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'selftest': selftest(args[0]); break;
    case 'seed': {
      const [owner, walletId, sigB64, out] = args;
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
    case 'seal': console.log(seal(fromHex(args[0], 32), agentSeed(), args[1]).toString('base64')); break;
    case 'open': {
      const [privFile, walletId, sealedB64, out] = args;
      writeSecret(out, hex(open(fromHex(readFileSync(privFile, 'utf8').trim(), 32), Buffer.from(sealedB64, 'base64'), walletId)));
      break;
    }
    default:
      console.error('usage: custody_agent.mjs selftest|seed|pub|headers|hash|half|https-half|verify-tee|execute-args|x25519-new|seal|open …');
      process.exit(2);
  }
} catch (e) {
  console.error(`custody_agent: ${e.message}`);
  process.exit(1);
}
