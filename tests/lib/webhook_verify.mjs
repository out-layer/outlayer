// Is a request a webhook OutLayer signed? What a receiver of a live suite and
// the reader of its log both ask, in one place. Node's own `crypto`; nothing
// to install.
//
// Every webhook carries
//
//   X-Webhook-Id                 the delivery's id: a random UUID, the same
//                                on each attempt; read here as opaque text
//   X-Webhook-Timestamp          unix seconds of the attempt
//   X-Webhook-Key-Id             which key of GET /wallet/v1/webhook-keys signed
//   X-Webhook-Signature-Ed25519  the signature, hex
//   X-Wallet-Id, X-Event-Type
//
// and, on an owner's event (X-Wallet-Id `owner:<account>`) only,
//
//   X-Webhook-Signature          the owner's HMAC of the body
//
// and the signature is over
//
//   outlayer-webhook-v1\n<id>\n<timestamp>\n<wallet id>\n<event type>\n<body>
//
// with the body as it was received.

import { createPublicKey, verify as verifySignature } from 'node:crypto';

/** How far a request's timestamp may be from the moment it was received. */
export const TOLERANCE_SEC = 300;

/** How long a key list is used before it is read again. */
const KEYS_TTL_MS = 10 * 60 * 1000;
/** The least time between two reads of the key list. */
const KEYS_READ_AGAIN_MS = 60 * 1000;
/** The most one read of the key list may take; a longer one has failed. */
const KEYS_READ_TIMEOUT_MS = 5 * 1000;

/** The header a suite puts on a request it sends to a receiver itself. */
export const REPLAY_HEADER = 'x-replayed-by-suite';

/** The DER prefix of an Ed25519 public key (SubjectPublicKeyInfo, RFC 8410). */
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * One header's value, the name in any case; null when absent or sent twice.
 * A log may hold a value as a list of one.
 */
export function header(headers, name) {
  if (typeof headers !== 'object' || headers === null) return null;
  let found = null;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    const one = Array.isArray(value) && value.length === 1 ? value[0] : value;
    if (found !== null || typeof one !== 'string') return null;
    found = one;
  }
  return found;
}

/**
 * The keys of `apiBase`, from GET /wallet/v1/webhook-keys. Throws with the
 * status, or the transport's code, when they cannot be read.
 */
export async function fetchKeys(apiBase) {
  let response;
  try {
    response = await fetch(`${apiBase.replace(/\/$/, '')}/wallet/v1/webhook-keys`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(KEYS_READ_TIMEOUT_MS),
    });
  } catch (e) {
    if (e.name === 'TimeoutError') throw new Error(`webhook-keys did not answer in ${KEYS_READ_TIMEOUT_MS / 1000} s`);
    throw new Error(`webhook-keys did not answer (${e.cause?.code ?? 'no code'})`);
  }
  if (response.status !== 200) throw new Error(`webhook-keys answered ${response.status}`);
  let parsed;
  try {
    parsed = await response.json();
  } catch {
    throw new Error('webhook-keys answered no JSON');
  }
  const keys = parsed?.keys;
  const whole = (k) => typeof k?.id === 'string' && k.algorithm === 'ed25519' && /^[0-9a-f]{64}$/i.test(k.public_key ?? '');
  if (!Array.isArray(keys) || keys.length === 0 || !keys.every(whole)) throw new Error('webhook-keys answered no list of ed25519 keys');
  return keys;
}

/**
 * The keys of `apiBase`, held as a receiver holds them: `get(keyId)` answers
 * the list, reading it when none is held or the one held is ten minutes old,
 * and — at most once a minute — when `keyId` is not in it. What is read
 * replaces what was held, so a key that left the list verifies nothing after
 * the next read. Requests that arrive during a read wait for that one read
 * and get its outcome. A clock that went back since a moment was noted has
 * passed any time counted from it. Throws when the list cannot be read and
 * none read in the last ten minutes is held. `now` is the clock, in
 * milliseconds.
 */
export function keyCache(apiBase, { read = fetchKeys, now = Date.now } = {}) {
  let held = null;
  let heldAt = 0;
  let triedAt = null;
  let reading = null;
  let lastFailure = null;
  const passed = (at, ms) => now() - at < 0 || now() - at >= ms;
  const readOnce = () => {
    if (reading === null) {
      triedAt = now();
      reading = read(apiBase)
        .then(
          (keys) => {
            held = keys;
            heldAt = now();
            lastFailure = null;
          },
          (e) => {
            lastFailure = e.message;
          },
        )
        .finally(() => {
          reading = null;
        });
    }
    return reading;
  };
  return {
    async get(keyId) {
      const fresh = () => held !== null && !passed(heldAt, KEYS_TTL_MS);
      const lacks = keyId !== undefined && keyId !== null && !(held ?? []).some((k) => k.id === keyId);
      if ((!fresh() || lacks) && (reading !== null || triedAt === null || passed(triedAt, KEYS_READ_AGAIN_MS))) await readOnce();
      if (!fresh()) throw new Error(lastFailure ?? 'webhook-keys could not be read, and no list read in the last ten minutes is held');
      return held;
    },
  };
}

/**
 * Judges one request.
 *
 *   headers   as Node gives them: lower-case names
 *   rawBody   a Buffer, or the text that was sent
 *   keys      of `fetchKeys`
 *   at        unix seconds the request was received; null: the time is not judged
 *
 * Answers {ok: true, id, timestamp, key_id, wallet_id, event_type,
 * owner_hmac}, or {ok: false, reason, …what could be read}. `owner_hmac` says
 * whether the request carried `X-Webhook-Signature`, and `owner_hmac_expected`
 * whether it should: an owner's event does, a wallet's does not. A reason is
 * one of
 *   no_signature     none of the signature's headers is there
 *   malformed        some are, and not all; or one holds what it cannot
 *   unknown_key      the key id is not among the keys
 *   bad_signature    the signature does not hold for these headers and body
 *   stale_timestamp  signed, and further from `at` than TOLERANCE_SEC
 */
export function judge({ headers, rawBody, keys, at }) {
  const id = header(headers, 'x-webhook-id');
  const timestamp = header(headers, 'x-webhook-timestamp');
  const keyId = header(headers, 'x-webhook-key-id');
  const signature = header(headers, 'x-webhook-signature-ed25519');
  const walletId = header(headers, 'x-wallet-id');
  const eventType = header(headers, 'x-event-type');
  const ownerHmac = (header(headers, 'x-webhook-signature') ?? '') !== '';
  const read = {
    id,
    key_id: keyId,
    wallet_id: walletId,
    event_type: eventType,
    owner_hmac: ownerHmac,
    owner_hmac_expected: (walletId ?? '').startsWith('owner:'),
  };
  const refused = (reason) => ({ ok: false, reason, ...read });

  if (id === null && timestamp === null && keyId === null && signature === null) return refused('no_signature');
  if ([id, timestamp, keyId, signature, walletId, eventType].includes(null)) return refused('malformed');
  if (!/^[0-9]{1,15}$/.test(timestamp) || !/^[0-9a-f]{128}$/i.test(signature)) return refused('malformed');

  const key = keys.find((k) => k.id === keyId && k.algorithm === 'ed25519');
  if (!key) return refused('unknown_key');

  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody ?? ''), 'utf8');
  const signed = Buffer.concat([Buffer.from(`outlayer-webhook-v1\n${id}\n${timestamp}\n${walletId}\n${eventType}\n`, 'utf8'), body]);
  const publicKey = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(key.public_key, 'hex')]), format: 'der', type: 'spki' });
  if (!verifySignature(null, signed, publicKey, Buffer.from(signature, 'hex'))) return refused('bad_signature');

  if (at !== null && Math.abs(at - Number(timestamp)) > TOLERANCE_SEC) return { ...refused('stale_timestamp'), timestamp: Number(timestamp) };
  return { ok: true, ...read, timestamp: Number(timestamp) };
}
