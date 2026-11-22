#!/usr/bin/env node
// A webhook receiver for the live suites: it verifies what it is sent,
// answers, and keeps a log the suite reads back (the shape
// `lib/tasks_hook.mjs` reads).
//
//   HOOK_TOKEN=<random> HOOK_PORT=<port> HOOK_API_BASE=<the API the suite runs against> \
//     node hook_receiver.mjs
//
// Every request is held to the signature a webhook of that API carries
// (`lib/webhook_verify.mjs`): the keys are read from
// `<HOOK_API_BASE>/wallet/v1/webhook-keys`, read again every ten minutes —
// what is read replaces what was held — and, at most once a minute, when a
// request names a key that is not among them. The verdict is kept with the
// request as `signature`: {"ok": true, "id", "timestamp", "key_id",
// "wallet_id", "event_type", "owner_hmac", "owner_hmac_expected"} — with
// "repeat": true when that delivery id was accepted before — or
// {"ok": false, "reason", …}. `owner_hmac` says whether the request carried
// `X-Webhook-Signature`; an owner's event does and a wallet's does not.
//
// Every path starts with the token, so nobody who does not hold it can send
// to the receiver or read what it was sent:
//
//   POST /<token>/hook            a webhook whose signature holds and whose
//                                 timestamp is within five minutes: 200
//                                 {"received": true}; any other: 401
//                                 {"received": false, "reason"}; 503 while
//                                 the keys cannot be read. Recorded in the
//                                 hook's log either way
//   GET  /<token>/hook/log        that log: {"requests": [...]}
//   POST /<token>/redirect        answered 307 to /<token>/hook, recorded in
//                                 its own log with its verdict (a receiver
//                                 that redirects, W3)
//   GET  /<token>/redirect/log    that log
//   GET  /<token>/health          200 "ok"
//   DELETE /<token>/hook/log, /<token>/redirect/log   empties that log
//
// Anything else is 404 with no body. It listens on 127.0.0.1 only; a tunnel
// (`tests/hook_receiver.sh`) makes it public. A request is kept as
// {"method", "headers", "body", "at", "signature"}; the body is the text
// sent, cut at MOST_BODY_BYTES. Each log keeps the last MOST_REQUESTS
// requests. Nothing is written to disk and nothing a request carries is
// printed.

import http from 'node:http';
import { judge, keyCache } from './webhook_verify.mjs';

const TOKEN = process.env.HOOK_TOKEN;
const PORT = Number(process.env.HOOK_PORT || 0);
const API_BASE = process.env.HOOK_API_BASE;
const MOST_BODY_BYTES = 64 * 1024;
// What is read of a body to judge its signature; a webhook is far smaller.
const MOST_READ_BYTES = 1024 * 1024;
const MOST_REQUESTS = 500;
// How long an accepted delivery id is remembered: past the time its
// signature is good for.
const ID_REMEMBERED_MS = 15 * 60 * 1000;

if (!TOKEN || TOKEN.length < 16 || !/^[A-Za-z0-9_-]+$/.test(TOKEN)) {
  console.error('HOOK_TOKEN must be at least 16 characters of [A-Za-z0-9_-]');
  process.exit(2);
}

if (!API_BASE || !/^https?:\/\/[^\s/]+/.test(API_BASE)) {
  console.error('HOOK_API_BASE must be the base URL of the API whose webhooks are received: its webhook-keys verify them');
  process.exit(2);
}

const logs = { hook: [], redirect: [] };

function keep(log, request, raw, signature) {
  const body = raw.subarray(0, MOST_BODY_BYTES).toString('utf8');
  log.push({ method: request.method, headers: request.headers, body, at: new Date().toISOString(), signature });
  if (log.length > MOST_REQUESTS) log.splice(0, log.length - MOST_REQUESTS);
}

/** The bytes sent, as they were sent. */
function readBody(request) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size <= MOST_READ_BYTES) chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', () => resolve(Buffer.alloc(0)));
  });
}

const keys = keyCache(API_BASE);

/** The verdict on one request, at the moment it was received. */
async function verdictOf(request, raw) {
  const at = Math.floor(Date.now() / 1000);
  const named = request.headers['x-webhook-key-id'];
  let held;
  try {
    held = await keys.get(typeof named === 'string' ? named : undefined);
  } catch (e) {
    return { ok: false, reason: 'keys_unavailable', detail: e.message };
  }
  return judge({ headers: request.headers, rawBody: raw, keys: held, at });
}

// Delivery ids accepted at /hook, and when. An id is opaque text.
const accepted = new Map();
/** True when `id` was accepted before; remembers it otherwise. */
function seenBefore(id) {
  const now = Date.now();
  for (const [known, at] of accepted) {
    if (now - at > ID_REMEMBERED_MS) accepted.delete(known);
  }
  if (accepted.has(id)) return true;
  accepted.set(id, now);
  return false;
}

function answer(response, status, body, headers = {}) {
  const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
  response.writeHead(status, { 'Content-Type': typeof body === 'string' ? 'text/plain' : 'application/json', ...headers });
  response.end(text);
}

const server = http.createServer(async (request, response) => {
  const path = (request.url || '').split('?')[0];
  const prefix = `/${TOKEN}/`;
  if (!path.startsWith(prefix)) return answer(response, 404);
  const route = path.slice(prefix.length);
  const body = await readBody(request);

  if (route === 'health' && request.method === 'GET') return answer(response, 200, 'ok');
  if (route === 'hook' && request.method === 'POST') {
    const signature = await verdictOf(request, body);
    if (signature.ok && seenBefore(signature.id)) signature.repeat = true;
    keep(logs.hook, request, body, signature);
    if (signature.ok) return answer(response, 200, signature.repeat ? { received: true, repeat: true } : { received: true });
    return answer(response, signature.reason === 'keys_unavailable' ? 503 : 401, { received: false, reason: signature.reason });
  }
  if (route === 'redirect' && request.method === 'POST') {
    keep(logs.redirect, request, body, await verdictOf(request, body));
    return answer(response, 307, undefined, { Location: `/${TOKEN}/hook` });
  }
  const log = route === 'hook/log' ? logs.hook : route === 'redirect/log' ? logs.redirect : null;
  if (log && request.method === 'GET') return answer(response, 200, { requests: log });
  if (log && request.method === 'DELETE') {
    log.length = 0;
    return answer(response, 200, { cleared: true });
  }
  return answer(response, 404);
});

server.listen(PORT, '127.0.0.1', () => {
  // The port only: the token stays out of every log.
  console.log(`hook receiver listening on 127.0.0.1:${server.address().port}`);
});
