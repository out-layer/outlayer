// What the owner's page does with a task, on WebCrypto alone — the browser's
// own, and Node's. The dashboard's inbox and the live suite (`tasks_e2e.sh`)
// both stand on these functions, and `worker/src/tasks/crypto.rs` is the other
// side of every one of them: the golden vectors in `tasks_page.test.mjs` are
// the ones pinned there.
//
// A device's private key is made non-extractable: the page can use it and
// cannot read it.
//
//   content          0x01 || nonce (12) || AES-256-GCM(content key, aad = task id)
//   to a public key  0x01 || ephemeral public key (65) || nonce (12) || AES-256-GCM
//                    key = HKDF-SHA256(ikm = ECDH x, salt = ephemeral || recipient, info)
//                    info = "outlayer-task:v1:" + purpose + ":" + task id

const subtle = globalThis.crypto.subtle;
const FORMAT = 0x01;
const POINT = 65;
const NONCE = 12;

export const Purpose = Object.freeze({
  DeviceCopy: 'device-copy',
  Answer: 'answer',
  Rejection: 'rejection',
  Note: 'note',
});

const utf8 = (text) => new TextEncoder().encode(text);

export function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function fromBase64Url(text) {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

export function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

export function fromHex(text) {
  return new Uint8Array(Buffer.from(text, 'hex'));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A public key as it is written: `p256:` and the uncompressed point, base64url. */
export function writePubkey(point) {
  return `p256:${toBase64Url(point)}`;
}

export function readPubkey(written) {
  if (!written.startsWith('p256:')) throw new Error('the key is not written `p256:…`');
  const point = fromBase64Url(written.slice(5));
  if (point.length !== POINT || point[0] !== 0x04) throw new Error('the key is not an uncompressed point of 65 bytes');
  return point;
}

/** A device: a key pair whose private half cannot be exported. */
export async function newDevice() {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const point = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return { privateKey: pair.privateKey, point, pubkey: writePubkey(point) };
}

/** A moment in the sentences the wallet signs: to the second, in UTC. */
function moment(unixSeconds) {
  return new Date(unixSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** The sentence the owner's wallet signs (NEP-413, recipient: the OutLayer contract). */
export function statement(account, devicePubkey, validUntil) {
  return `Sign in to OutLayer as ${account}. Device key: ${devicePubkey}. Valid until ${moment(validUntil)}.`;
}

/**
 * The sentence the owner's wallet signs to confirm one action a session must
 * not do alone: `{ withdraw_device: id }`, `{ name_webhook: url }` (named by
 * its SHA-256) or `{ remove_webhook: true }`. Good for ten minutes, once.
 */
export async function confirmation(account, action, at) {
  let named;
  if ('withdraw_device' in action) named = `withdraw the device ${action.withdraw_device}`;
  else if ('name_webhook' in action) {
    const digest = await subtle.digest('SHA-256', new TextEncoder().encode(action.name_webhook));
    named = `name the webhook ${toHex(new Uint8Array(digest))}`;
  } else named = 'remove the webhook';
  return `Confirm in OutLayer as ${account}: ${named}. At ${moment(at)}.`;
}

/**
 * The sentence the owner's wallet signs to approve one task: the task, the
 * hash of the envelope the page opened, and the digest of what the owner
 * wrote, sealed. The coordinator and the enclave each rebuild it and compare
 * bytes. Good for ten minutes at the door, once.
 */
export function approval(account, id, hash, digest, at) {
  return `Approve in OutLayer as ${account}: task ${id} with hash ${hash} and supply ${digest}. At ${moment(at)}.`;
}

/**
 * The digest the approval names of what the owner said: SHA-256, hex, of
 * `{"note":<base64|null>,"supplied":<base64|null>}` over the sealed bytes as
 * base64, members in that order, no whitespace. Nothing said is still a
 * digest.
 */
export async function supplyDigest(sealedSupplied, sealedNote) {
  const canonical = JSON.stringify({ note: sealedNote ?? null, supplied: sealedSupplied ?? null });
  return toHex(new Uint8Array(await subtle.digest('SHA-256', utf8(canonical))));
}

async function eciesKey(privateKey, theirPoint, ephemeralPoint, recipientPoint, purpose, task, usage) {
  const theirs = await subtle.importKey('raw', theirPoint, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: theirs }, privateKey, 256);
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: concat(ephemeralPoint, recipientPoint),
      info: utf8(`outlayer-task:v1:${purpose}:${task}`),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

/** Open what was encrypted to this key for `purpose` of `task`. */
export async function openFrom(privateKey, ownPoint, purpose, task, blob) {
  if (blob.length < 1 + POINT + NONCE + 16 || blob[0] !== FORMAT) throw new Error('decryption failed');
  const ephemeral = blob.slice(1, 1 + POINT);
  const nonce = blob.slice(1 + POINT, 1 + POINT + NONCE);
  try {
    const key = await eciesKey(privateKey, ephemeral, ephemeral, ownPoint, purpose, task, 'decrypt');
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, blob.slice(1 + POINT + NONCE)));
  } catch {
    throw new Error('decryption failed');
  }
}

/** Encrypt `plaintext` to a public key for `purpose` of `task`. */
export async function sealTo(recipientPoint, purpose, task, plaintext) {
  const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const ephemeralPoint = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey));
  const key = await eciesKey(ephemeral.privateKey, recipientPoint, ephemeralPoint, recipientPoint, purpose, task, 'encrypt');
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE));
  const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext));
  return concat(new Uint8Array([FORMAT]), ephemeralPoint, nonce, sealed);
}

async function openUnder(contentKey, bound, blob) {
  if (blob.length < 1 + NONCE + 16 || blob[0] !== FORMAT) throw new Error('decryption failed');
  try {
    const key = await subtle.importKey('raw', contentKey, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv: blob.slice(1, 1 + NONCE), additionalData: utf8(bound) },
        key,
        blob.slice(1 + NONCE),
      ),
    );
  } catch {
    throw new Error('decryption failed');
  }
}

/** The content of `task` under its content key: the envelope's document. */
export function openContent(contentKey, task, blob) {
  return openUnder(contentKey, task, blob);
}

/** The file at `at` of `task`, held to what the task's envelope says of it. */
export async function openFile(contentKey, task, at, note, blob) {
  const bytes = await openUnder(contentKey, `${task}:file:${at}`, blob);
  const hash = toHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
  if (bytes.length !== note.size || hash !== note.sha256) throw new Error('the file that opened is not the file the task names');
  return bytes;
}

/**
 * Read a task of the inbox on this device: the envelope, and the hash the
 * owner's answer names. The hash is of the bytes that were opened — what is
 * shown is what is hashed. Throws when the task is not the one the inbox
 * says it is.
 */
export async function readTask(device, task) {
  if (task.device_copy == null) throw new Error('the task is locked on this device');
  const contentKey = await openFrom(
    device.privateKey,
    device.point,
    Purpose.DeviceCopy,
    task.id,
    new Uint8Array(Buffer.from(task.device_copy, 'base64')),
  );
  const document = await openContent(contentKey, task.id, new Uint8Array(Buffer.from(task.content, 'base64')));
  const envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(document));
  if (envelope.id !== task.id) throw new Error('the task opened is not the task listed');
  const hash = toHex(new Uint8Array(await subtle.digest('SHA-256', document)));
  return { envelope, hash, contentKey };
}

/** What the owner supplies with an answer, or the reason of a rejection. */
export async function writeReply(envelope, purpose, text) {
  return sealTo(readPubkey(envelope.reply_pubkey), purpose, envelope.id, utf8(text));
}

// ── the owner's wallet, for a suite that plays the owner ─────────────────────

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function fromBase58(text) {
  let value = 0n;
  for (const char of text) {
    const digit = BASE58.indexOf(char);
    if (digit < 0) throw new Error('not base58');
    value = value * 58n + BigInt(digit);
  }
  const bytes = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  for (const char of text) {
    if (char !== '1') break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

export function toBase58(bytes) {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let text = '';
  while (value > 0n) {
    text = BASE58[Number(value % 58n)] + text;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    text = '1' + text;
  }
  return text;
}

function borshString(text) {
  const bytes = utf8(text);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, bytes.length, true);
  return concat(length, bytes);
}

/** What a NEP-413 signature signs: SHA-256 of the tag and the Borsh payload. */
export async function nep413Digest(message, nonce, recipient) {
  const tag = new Uint8Array(4);
  new DataView(tag.buffer).setUint32(0, 2147484061, true);
  const payload = concat(tag, borshString(message), nonce, borshString(recipient), new Uint8Array([0]));
  return new Uint8Array(await subtle.digest('SHA-256', payload));
}

/**
 * The statement of a device, signed by a wallet key: the body of
 * `POST /inbox/session`. `secretKey` is a NEAR key as its file holds it,
 * `ed25519:` and base58 of the seed and the public key; it is used here and
 * returned nowhere.
 */
export async function signStatement({ account, secretKey, devicePubkey, validUntil, nonce, recipient }) {
  const signed = await signSentence({ secretKey, message: statement(account, devicePubkey, validUntil), nonce, recipient });
  return { account_id: account, device_pubkey: devicePubkey, valid_until: validUntil, ...signed };
}

/** The owner's confirmation of `action`, signed by the wallet key, as a request carries it. */
export async function signConfirmation({ account, secretKey, action, at, nonce, recipient }) {
  const signed = await signSentence({ secretKey, message: await confirmation(account, action, at), nonce, recipient });
  return { at, ...signed };
}

/**
 * The owner's approval of one task, signed by the wallet key, as
 * `POST /inbox/tasks/{id}/approve` carries it: `{at, public_key, signature,
 * nonce}`. `supplied` and `note` are the sealed bytes as base64, or null. The
 * sentence names `id` and `hash` as given — a row that signs for the wrong
 * task or hash passes them so.
 */
export async function signApproval({ account, secretKey, id, hash, supplied, note, at, nonce, recipient }) {
  const digest = await supplyDigest(supplied ?? null, note ?? null);
  const signed = await signSentence({ secretKey, message: approval(account, id, hash, digest, at), nonce, recipient });
  return { at, ...signed };
}

/** One NEP-413 signature over `message` by a NEAR key as its file holds it; the key is returned nowhere. */
async function signSentence({ secretKey, message, nonce, recipient }) {
  const raw = fromBase58(secretKey.replace(/^ed25519:/, ''));
  if (raw.length !== 64 && raw.length !== 32) throw new Error('the wallet key is not an ed25519 key');
  const seed = raw.slice(0, 32);
  // PKCS#8 of an Ed25519 private key: a fixed prefix and the seed.
  const pkcs8 = concat(fromHex('302e020100300506032b657004220420'), seed);
  const key = await subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
  const digest = await nep413Digest(message, nonce, recipient);
  const signature = new Uint8Array(await subtle.sign('Ed25519', key, digest));
  const jwk = await subtle.exportKey('jwk', await subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']));
  const publicKey = fromBase64Url(jwk.x);
  return {
    public_key: `ed25519:${toBase58(publicKey)}`,
    signature: Buffer.from(signature).toString('base64'),
    nonce: Buffer.from(nonce).toString('base64'),
  };
}
