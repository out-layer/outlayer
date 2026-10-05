#!/usr/bin/env node
// A webhook receiver for the live suites: it answers what it is sent and
// keeps a log the suite reads back (the shape `lib/tasks_hook.mjs` reads).
//
//   HOOK_TOKEN=<random> HOOK_PORT=<port> node hook_receiver.mjs
//
// Every path starts with the token, so nobody who does not hold it can send
// to the receiver or read what it was sent:
//
//   POST /<token>/hook            answered 200, recorded in the hook's log
//   GET  /<token>/hook/log        that log: {"requests": [...]}
//   POST /<token>/redirect        answered 307 to /<token>/hook, recorded in
//                                 its own log (a receiver that redirects, W3)
//   GET  /<token>/redirect/log    that log
//   GET  /<token>/health          200 "ok"
//   DELETE /<token>/hook/log, /<token>/redirect/log   empties that log
//
// Anything else is 404 with no body. It listens on 127.0.0.1 only; a tunnel
// (`tests/hook_receiver.sh`) makes it public. A request is kept as
// {"method", "headers", "body", "at"}; the body is the text sent, cut at
// MOST_BODY_BYTES. Each log keeps the last MOST_REQUESTS requests. Nothing is
// written to disk and nothing a request carries is printed.

import http from 'node:http';

const TOKEN = process.env.HOOK_TOKEN;
const PORT = Number(process.env.HOOK_PORT || 0);
const MOST_BODY_BYTES = 64 * 1024;
const MOST_REQUESTS = 500;

if (!TOKEN || TOKEN.length < 16 || !/^[A-Za-z0-9_-]+$/.test(TOKEN)) {
  console.error('HOOK_TOKEN must be at least 16 characters of [A-Za-z0-9_-]');
  process.exit(2);
}

const logs = { hook: [], redirect: [] };

function keep(log, request, body) {
  log.push({ method: request.method, headers: request.headers, body, at: new Date().toISOString() });
  if (log.length > MOST_REQUESTS) log.splice(0, log.length - MOST_REQUESTS);
}

function readBody(request) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size <= MOST_BODY_BYTES) chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').slice(0, MOST_BODY_BYTES)));
    request.on('error', () => resolve(''));
  });
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
    keep(logs.hook, request, body);
    return answer(response, 200, { received: true });
  }
  if (route === 'redirect' && request.method === 'POST') {
    keep(logs.redirect, request, body);
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
