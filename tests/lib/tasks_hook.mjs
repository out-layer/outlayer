#!/usr/bin/env node
// What a webhook receiver of a suite was sent, read back from the receiver's
// log: what `tasks_e2e.sh` uses to see the events an owner is told of a task.
//
//   node tasks_hook.mjs events [needle…]
//
// Reads from the environment:
//   HOOK_LOG_URL   where the receiver's log is read, with GET. It may carry a
//                  token, so it is never printed and never on a command line.
//
// The log is JSON: an array of the requests the receiver was sent, in any
// order, or an object holding that array under `requests`. A request is
//
//   {"method": "POST", "headers": {"<name>": "<value>", …}, "body": <body>}
//
// where `body` is the text that was sent, or the JSON it parses to. Header
// names are read in any case; a value may be a text or a list of texts.
//
// `events` prints one JSON document:
//
//   {"status", "requests", "events": [ … ], "leaked": [ … ]}
//
// An event is a request whose body is an object with a `type` and a `task_id`:
// its `type`, `task_id`, `owner`, `preparer`, `kind`, `state`, `run`, `link`,
// the names of the body's members (`members`), whether the request carried
// `X-Webhook-Signature` (`signed`), and its `X-Wallet-Id` and `X-Event-Type`.
// `leaked` lists the needles found in the body of any request. Neither the
// log's URL nor a request's body is printed.

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

const commands = {
  async events(needles) {
    const log = await readLog();
    if (log.requests === null) return { status: log.status, failed: "the receiver's log answered no 200" };
    const events = [];
    const leaked = new Set();
    for (const request of log.requests) {
      const { text, parsed } = bodyOf(request);
      for (const needle of needles) {
        if (needle !== '' && text.includes(needle)) leaked.add(needle);
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
        wallet_id: header(request.headers, 'x-wallet-id'),
        event_type: header(request.headers, 'x-event-type'),
      });
    }
    return { status: 200, requests: log.requests.length, events, leaked: [...leaked] };
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
