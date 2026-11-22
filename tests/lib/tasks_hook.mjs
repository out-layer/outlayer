#!/usr/bin/env node
// What a webhook receiver of a suite was sent, read back from the receiver's
// log: what `tasks_e2e.sh` uses to see the events an owner is told of a task.
//
//   node tasks_hook.mjs events [needle…]
//   node tasks_hook.mjs replay swapped-wallet|tampered-body|no-signature|again|stale
//
// Reads from the environment:
//   HOOK_LOG_URL     where the receiver's log is read, with GET. It may carry
//                    a token, so it is never printed and never on a command
//                    line.
//   COORDINATOR_URL  the API the suite runs against: every request of the log
//                    is verified under its `GET /wallet/v1/webhook-keys`,
//                    read once (`lib/webhook_verify.mjs`).
//   HOOK_URL         (`replay`) the receiver itself; a secret like the log's.
//
// The log is JSON: an array of the requests the receiver was sent, in any
// order, or an object holding that array under `requests`. A request is
//
//   {"method": "POST", "headers": {"<name>": "<value>", …}, "body": <body>, "at": <when received>}
//
// where `body` is the text that was sent, or the JSON it parses to. Header
// names are read in any case; a value may be a text or a list of one. `at`
// is an ISO time; a signature's timestamp is held to it, and not judged where
// a log has none. A signature is verified over the text that was sent: a log
// that keeps a body only as parsed JSON does not verify.
//
// `events` prints one JSON document:
//
//   {"status", "requests", "events": [ … ], "leaked": [ … ], "unverified": [ … ],
//    "misdressed": [ … ], "wallet_events", "replays", "receiver_verifies",
//    "receiver_keys_unavailable", "under_retired_key"}
//
// An event is a request whose body is an object with a `type` and a `task_id`:
// its `type`, `task_id`, `owner`, `preparer`, `kind`, `state`, `run`, `link`,
// the names of the body's members (`members`), whether the request carried
// the owner's `X-Webhook-Signature` (`signed`), whether its Ed25519 signature
// holds (`verified`; `refusal` says why not), its delivery id (`webhook_id`),
// and its `X-Wallet-Id` and `X-Event-Type`.
// `unverified` lists every POST of the log whose signature does not hold —
// an event or not — as {"reason", "webhook_id", "wallet_id", "event_type"}:
// a suite fails on one. A POST signed under a key that has left webhook-keys,
// which the receiver verified when it arrived, is counted in
// `under_retired_key` instead: the key held then, today's list cannot say. `misdressed` lists, in the same shape, every verified
// POST that carries `X-Webhook-Signature` without being an owner's event
// (`X-Wallet-Id` `owner:<account>`), or is one and carries none; a suite
// fails on one too. `wallet_events` counts the verified POSTs that are not an
// owner's. `leaked` lists the needles found in the body of any
// request. A request the suite sent itself (`replay`) is counted in `replays`
// and is neither an event nor unverified. `receiver_verifies` says whether
// the receiver kept verdicts of its own, and `receiver_keys_unavailable` how
// many requests it answered 503 because it could not read the webhook-keys:
// the receiver's failure, not a webhook's — the delivery is tried again, and
// the request is judged here like any other. Neither a URL nor a request's body
// is printed.
//
// `replay <mode>` sends one webhook of the log to the receiver again, marked
// as the suite's, and prints {"mode", "status", "reason", "repeat", "age_sec"}
// — what the receiver answered — or {"skipped": why}:
//   swapped-wallet  the newest verified one, with another X-Wallet-Id
//   tampered-body   the newest verified one, with a byte added to the body
//   no-signature    the newest verified one, without the signature's headers
//   again           the newest verified one, as it was
//   stale           the oldest verified one, as it was — when it is older
//                   than the signature's five minutes

import { REPLAY_HEADER, TOLERANCE_SEC, fetchKeys, judge } from './webhook_verify.mjs';

function need(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

function header(headers, name) {
  if (typeof headers !== 'object' || headers === null) return null;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    const first = Array.isArray(value) ? value[0] : value;
    return typeof first === 'string' ? first : null;
  }
  return null;
}

/** A request's body as text and, when it is a JSON object, as that object. */
function bodyOf(request) {
  const body = request?.body;
  if (typeof body === 'string') {
    let parsed = null;
    try {
      parsed = JSON.parse(body);
    } catch {
      parsed = null;
    }
    return { text: body, parsed };
  }
  if (typeof body === 'object' && body !== null) return { text: JSON.stringify(body), parsed: body };
  return { text: '', parsed: null };
}

async function readLog() {
  const url = need('HOOK_LOG_URL');
  let response;
  try {
    response = await fetch(url, { headers: { Accept: 'application/json' } });
  } catch (e) {
    // The error of the transport names the URL; its code does not.
    throw new Error(`the receiver's log did not answer (${e.cause?.code ?? 'no code'})`);
  }
  const text = await response.text();
  if (response.status !== 200) return { status: response.status, requests: null };
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("the receiver's log is not JSON");
  }
  const requests = Array.isArray(parsed) ? parsed : parsed?.requests;
  if (!Array.isArray(requests)) throw new Error("the receiver's log is neither a list of requests nor an object with `requests`");
  return { status: 200, requests };
}

/** When a request was received, unix seconds; null where the log does not say. */
function receivedAt(request) {
  const at = typeof request?.at === 'string' ? Date.parse(request.at) : NaN;
  return Number.isNaN(at) ? null : Math.floor(at / 1000);
}

const isPost = (request) => (request?.method ?? 'POST') === 'POST';
const isReplay = (request) => header(request?.headers, REPLAY_HEADER) !== null;

/** The log's own webhooks whose signature holds, each with its verdict, oldest first. */
function verifiedOf(requests, keys) {
  return requests
    .filter((request) => isPost(request) && !isReplay(request))
    .map((request) => ({ request, at: receivedAt(request), verdict: judge({ headers: request.headers, rawBody: bodyOf(request).text, keys, at: receivedAt(request) }) }))
    .filter((one) => one.verdict.ok)
    .sort((a, b) => (a.at ?? 0) - (b.at ?? 0));
}

const SIGNATURE_HEADERS = ['x-webhook-id', 'x-webhook-timestamp', 'x-webhook-key-id', 'x-webhook-signature-ed25519'];
const SENT_AGAIN = [...SIGNATURE_HEADERS, 'x-wallet-id', 'x-event-type', 'x-webhook-signature', 'content-type'];

const REPLAY_MODES = {
  'swapped-wallet': (headers, body) => ({ headers: { ...headers, 'x-wallet-id': `${headers['x-wallet-id']}.swapped` }, body }),
  'tampered-body': (headers, body) => ({ headers, body: `${body} ` }),
  'no-signature': (headers, body) => ({ headers: Object.fromEntries(Object.entries(headers).filter(([name]) => !SIGNATURE_HEADERS.includes(name))), body }),
  again: (headers, body) => ({ headers, body }),
  stale: (headers, body) => ({ headers, body }),
};

const commands = {
  async events(needles) {
    const log = await readLog();
    if (log.requests === null) return { status: log.status, failed: "the receiver's log answered no 200" };
    const keys = await fetchKeys(need('COORDINATOR_URL'));
    const events = [];
    const leaked = new Set();
    const unverified = [];
    const misdressed = [];
    let walletEvents = 0;
    let replays = 0;
    let underRetiredKey = 0;
    for (const request of log.requests) {
      const { text, parsed } = bodyOf(request);
      for (const needle of needles) {
        if (needle !== '' && text.includes(needle)) leaked.add(needle);
      }
      if (isReplay(request)) {
        replays += 1;
        continue;
      }
      const verdict = judge({ headers: request.headers, rawBody: text, keys, at: receivedAt(request) });
      // Signed under a key that has since left webhook-keys, and verified by the receiver
      // when it arrived: the delivery held then; today's list cannot judge it again.
      if (isPost(request) && !verdict.ok && verdict.reason === 'unknown_key' && request.signature?.ok === true) {
        underRetiredKey += 1;
        continue;
      }
      if (isPost(request) && !verdict.ok) {
        unverified.push({ reason: verdict.reason, webhook_id: verdict.id, wallet_id: verdict.wallet_id, event_type: verdict.event_type });
      }
      if (isPost(request) && verdict.ok) {
        if (!verdict.owner_hmac_expected) walletEvents += 1;
        if (verdict.owner_hmac !== verdict.owner_hmac_expected) {
          const reason = verdict.owner_hmac ? 'a wallet event with X-Webhook-Signature' : "an owner's event without X-Webhook-Signature";
          misdressed.push({ reason, webhook_id: verdict.id, wallet_id: verdict.wallet_id, event_type: verdict.event_type });
        }
      }
      const told = parsed !== null && !Array.isArray(parsed) && typeof parsed.type === 'string' && typeof parsed.task_id === 'string';
      if (!told) continue;
      events.push({
        type: parsed.type,
        task_id: parsed.task_id,
        owner: parsed.owner ?? null,
        preparer: parsed.preparer ?? null,
        kind: parsed.kind ?? null,
        state: parsed.state ?? null,
        run: parsed.run ?? null,
        link: parsed.link ?? null,
        members: Object.keys(parsed).sort(),
        signed: (header(request.headers, 'x-webhook-signature') ?? '') !== '',
        verified: verdict.ok,
        refusal: verdict.ok ? null : verdict.reason,
        webhook_id: verdict.id,
        wallet_id: header(request.headers, 'x-wallet-id'),
        event_type: header(request.headers, 'x-event-type'),
      });
    }
    return {
      status: 200,
      requests: log.requests.length,
      events,
      leaked: [...leaked],
      unverified,
      under_retired_key: underRetiredKey,
      misdressed,
      wallet_events: walletEvents,
      replays,
      receiver_verifies: log.requests.some((request) => typeof request?.signature?.ok === 'boolean'),
      receiver_keys_unavailable: log.requests.filter((request) => request?.signature?.reason === 'keys_unavailable').length,
    };
  },

  async replay([mode]) {
    const change = REPLAY_MODES[mode];
    if (!change) throw new Error(`unknown mode ${mode ?? ''}; one of: ${Object.keys(REPLAY_MODES).join(', ')}`);
    const receiver = need('HOOK_URL');
    const log = await readLog();
    if (log.requests === null) return { mode, failed: "the receiver's log answered no 200" };
    const verified = verifiedOf(log.requests, await fetchKeys(need('COORDINATOR_URL')));
    if (verified.length === 0) return { mode, skipped: 'the log holds no webhook whose signature holds' };
    const picked = mode === 'stale' ? verified[0] : verified[verified.length - 1];
    const age = Math.floor(Date.now() / 1000) - picked.verdict.timestamp;
    if (mode === 'stale' && age <= TOLERANCE_SEC) {
      return { mode, skipped: `the oldest webhook of the log was signed ${age} s ago; a signature is good for ${TOLERANCE_SEC} s`, age_sec: age };
    }
    if (mode !== 'stale' && age > TOLERANCE_SEC) {
      return { mode, skipped: `the newest webhook of the log was signed ${age} s ago: past the ${TOLERANCE_SEC} s a signature is good for`, age_sec: age };
    }
    const kept = {};
    for (const name of SENT_AGAIN) {
      const value = header(picked.request.headers, name);
      if (value !== null) kept[name] = value;
    }
    const sent = change(kept, bodyOf(picked.request).text);
    let response;
    try {
      response = await fetch(receiver, { method: 'POST', headers: { ...sent.headers, [REPLAY_HEADER]: '1' }, body: sent.body, redirect: 'manual' });
    } catch (e) {
      throw new Error(`the receiver did not answer (${e.cause?.code ?? 'no code'})`);
    }
    let said = null;
    try {
      said = JSON.parse(await response.text());
    } catch {
      said = null;
    }
    return { mode, status: response.status, reason: said?.reason ?? null, repeat: said?.repeat === true, age_sec: age };
  },
};

const [command, ...args] = process.argv.slice(2);
const run = commands[command];
if (!run) {
  console.error(`unknown command ${command ?? ''}; one of: ${Object.keys(commands).join(', ')}`);
  process.exit(2);
}
try {
  console.log(JSON.stringify(await run(args)));
} catch (e) {
  console.log(JSON.stringify({ failed: e.message }));
  process.exit(1);
}
