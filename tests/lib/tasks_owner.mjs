#!/usr/bin/env node
// The owner's page, played from a shell: what `tasks_e2e.sh` uses to sign in,
// read the inbox, open a file and write what an owner writes.
//
//   node tasks_owner.mjs <command> [args…]
//
// Reads from the environment:
//   INBOX_URL      the coordinator
//   OWNER          the owner's account
//   OWNER_KEY_FILE a near-cli credentials file of that account (`private_key`);
//                  `sign-in` takes another file as its second argument
//   RECIPIENT      the OutLayer contract the statement is signed for
//   STATE_DIR      where this device lives between calls: its key pair and
//                  its session's token. A directory of the suite's own, mode
//                  700, deleted when the suite ends.
//
// Nothing secret is printed: not the wallet key, not the token, not the
// device's key, not a webhook's URL. A command prints one JSON document on
// stdout.
//
//   sign-in [device] [key-file]      open a session on a device (default `a`),
//                                    signed with the key of `key-file` when one
//                                    is named
//   sign-in-stranger [device]        the same, signed with a key made on the
//                                    spot, which is on no account
//   keygen <name>                    make an ed25519 key, keep it in STATE_DIR
//                                    as a credentials file; prints
//                                    {"public_key", "file"}
//   list [device] [waiting|closed]   the inbox, each task read where it opens
//   file <task> <n> [device]         open one file: its size and hash
//   proof <task> [device]            the run that made the task, its attestation,
//                                    and whether its answer names the task
//   seal <task> answer|rejection <text> [device]   what the owner writes, sealed
//   reject <task> [text] [device]    say no, with a reason
//   delete <task> [device]           delete one
//   mute <agent|project> <subject> [device]
//   unmute <agent|project> <subject> [device]
//   devices [device]                 the devices signed in, and whether the one
//                                    marked `this` is this device
//   webhook get [device] [VARIABLE]  where the owner is told of a task: whether a
//                                    URL is set, when and by which key, and
//                                    whether it is the URL the environment
//                                    variable VARIABLE holds
//   webhook set <VARIABLE> [device] [signed|unsigned]
//                                    name the URL that VARIABLE holds, signed
//                                    for by the owner's wallet key (or not)
//   webhook delete [device] [signed|unsigned]
//   withdraw <id> [device] [signed|unsigned]
//                                    withdraw another device of the account
//   sign-out [device]
//   raw <METHOD> <path> [body] [device|none|garbage]   one request as it is;
//                                    prints {"status", "body", "retry_after"}
//   flood <count> [path] [device|none]   GET `path` up to `count` times, eight
//                                    at once, until one is answered 429; prints
//                                    how many were sent, the statuses, and what
//                                    the 429 said

import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  Purpose, fromBase64Url, fromHex, openFile, readPubkey, readTask, signConfirmation, signStatement, toBase58, toHex, writePubkey,
  writeReply,
} from './tasks_page.mjs';

const subtle = globalThis.crypto.subtle;
const CURVE = { name: 'ECDH', namedCurve: 'P-256' };

/** Does a run's answer name the task `id` with the hash `hash`, anywhere in it? */
function namesTask(output, id, hash) {
  let parsed;
  try {
    parsed = JSON.parse(output);
    if (typeof parsed === 'string') parsed = JSON.parse(parsed);
  } catch {
    return false;
  }
  const within = (value, depth) => {
    if (depth > 16 || typeof value !== 'object' || value === null) return false;
    if (Array.isArray(value)) return value.some((entry) => within(entry, depth + 1));
    if (value.task_id === id && typeof value.task_hash === 'string' && value.task_hash.toLowerCase() === hash.toLowerCase()) return true;
    return Object.values(value).some((entry) => within(entry, depth + 1));
  };
  return within(parsed, 0);
}

function need(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

function stateDir() {
  const dir = need('STATE_DIR');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function statePath(device) {
  return join(stateDir(), `device-${device}.json`);
}

function saveState(device, state) {
  const path = statePath(device);
  writeFileSync(path, JSON.stringify(state), { mode: 0o600 });
  chmodSync(path, 0o600);
}

function loadState(device) {
  const path = statePath(device);
  if (!existsSync(path)) throw new Error(`the device ${device} has not signed in`);
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** The token a request carries: a device's, none, or one that is no session's. */
function tokenOf(device) {
  if (device === 'none') return undefined;
  if (device === 'garbage') return `os_${'0'.repeat(64)}`;
  return loadState(device).token;
}

/** An ed25519 key as a NEAR credentials file holds it. */
async function makeWalletKey() {
  const pair = await subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const jwk = await subtle.exportKey('jwk', pair.privateKey);
  const seed = fromBase64Url(jwk.d);
  const point = fromBase64Url(jwk.x);
  const both = new Uint8Array(64);
  both.set(seed, 0);
  both.set(point, 32);
  return { public_key: `ed25519:${toBase58(point)}`, private_key: `ed25519:${toBase58(both)}` };
}

/**
 * The owner's confirmation of one action, signed by the wallet key of
 * OWNER_KEY_FILE (or the file given): what withdrawing another device and
 * naming or removing the webhook carry beside the session's token.
 */
async function confirmed(action, keyFile) {
  const secretKey = JSON.parse(readFileSync(keyFile || need('OWNER_KEY_FILE'), 'utf8')).private_key;
  return signConfirmation({
    account: need('OWNER'),
    secretKey,
    action,
    at: Math.floor(Date.now() / 1000) + Number(process.env.CONFIRM_AT_OFFSET ?? 0),
    nonce: globalThis.crypto.getRandomValues(new Uint8Array(32)),
    recipient: need('RECIPIENT'),
  });
}

/** Sign a device in with `secretKey`; the session is kept only when one opened. */
async function openSession(device, secretKey) {
  const made = await makeDevice();
  const statement = await signStatement({
    account: need('OWNER'),
    secretKey,
    devicePubkey: made.pubkey,
    validUntil: Math.floor(Date.now() / 1000) + Number(process.env.SESSION_SECONDS ?? 3600),
    nonce: globalThis.crypto.getRandomValues(new Uint8Array(32)),
    recipient: need('RECIPIENT'),
  });
  const answer = await request('POST', '/inbox/session', { body: statement });
  if (answer.status === 200) {
    saveState(device, { ...made, token: answer.body.token, device_id: answer.body.device_id, statement });
  }
  const { token: _, ...shown } = typeof answer.body === 'object' && answer.body !== null ? answer.body : { said: answer.body };
  return {
    status: answer.status,
    ...shown,
    signed_by: statement.public_key,
    token_returned: answer.status === 200 && typeof answer.body.token === 'string',
  };
}

/** A webhook's answer without its URL, which may carry a token. */
function webhookShown(answer, expected) {
  const body = typeof answer.body === 'object' && answer.body !== null ? answer.body : {};
  const url = typeof body.url === 'string' ? body.url : null;
  return {
    status: answer.status,
    url_set: url !== null,
    url_matches: expected === undefined ? null : url === expected,
    set_at: body.set_at ?? null,
    set_by_key: body.set_by_key ?? null,
    set_here: body.set_here ?? null,
    // The secret is told once, and printed never: only that it was told.
    secret_told: typeof body.secret === 'string',
    reason: body.reason ?? null,
  };
}

// A device of a suite keeps its key in a file between calls, so here it is
// made exportable; the page's is not (`newDevice`, and V4 of the suite).
async function makeDevice() {
  const pair = await subtle.generateKey(CURVE, true, ['deriveBits']);
  const point = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  return { pkcs8: toHex(pkcs8), pubkey: writePubkey(point) };
}

async function deviceOf(state) {
  const privateKey = await subtle.importKey('pkcs8', fromHex(state.pkcs8), CURVE, false, ['deriveBits']);
  return { privateKey, point: readPubkey(state.pubkey), pubkey: state.pubkey };
}

async function request(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${need('INBOX_URL')}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  const limit_headers = [...response.headers.keys()].filter((name) => /ratelimit|rate-limit/i.test(name));
  return {
    status: response.status,
    body: parsed ?? text,
    retry_after: response.headers.get('retry-after'),
    limit_headers,
  };
}

/** A request that must succeed; its body. */
async function ask(method, path, options) {
  const answer = await request(method, path, options);
  if (answer.status !== 200) {
    throw new Error(`${method} ${path} answered ${answer.status}: ${JSON.stringify(answer.body).slice(0, 300)}`);
  }
  return answer.body;
}

async function listed(state, show) {
  const { tasks } = await ask('GET', `/inbox/tasks?show=${show}`, { token: state.token });
  const device = await deviceOf(state);
  const out = [];
  for (const task of tasks) {
    const row = {
      id: task.id,
      project_id: task.project_id,
      project_uuid: task.project_uuid,
      preparer: task.preparer,
      profile: task.profile,
      kind: task.kind,
      state: task.state,
      run: task.run ?? null,
      locked: task.locked,
      has_content: task.content !== null,
      has_copy: task.device_copy !== null,
      read: null,
      unread: null,
    };
    if (task.content !== null && task.device_copy !== null) {
      try {
        const read = await readTask(device, task);
        const same =
          read.envelope.owner === need('OWNER') &&
          read.envelope.project === task.project_id &&
          read.envelope.preparer === task.preparer;
        if (!same) throw new Error('the task that opened is not the task listed');
        row.read = { envelope: read.envelope, hash: read.hash };
      } catch (e) {
        row.unread = e.message;
      }
    }
    out.push(row);
  }
  return out;
}

async function readOne(state, id) {
  const { tasks } = await ask('GET', '/inbox/tasks?show=waiting', { token: state.token });
  const task = tasks.find((t) => t.id === id);
  if (!task) throw new Error(`the task ${id} does not wait for this owner`);
  return { task, read: await readTask(await deviceOf(state), task) };
}

const commands = {
  async 'sign-in'([device = 'a', keyFile = '']) {
    const secretKey = JSON.parse(readFileSync(keyFile || need('OWNER_KEY_FILE'), 'utf8')).private_key;
    return openSession(device, secretKey);
  },

  // A statement whose signature verifies, by a key the account does not have.
  async 'sign-in-stranger'([device = 'stranger']) {
    return openSession(device, (await makeWalletKey()).private_key);
  },

  async keygen([name = '']) {
    if (!/^[a-z0-9-]{1,32}$/.test(name)) throw new Error('a key is named in lower-case letters, digits and dashes');
    const key = await makeWalletKey();
    const file = join(stateDir(), `key-${name}.json`);
    writeFileSync(file, JSON.stringify({ account_id: need('OWNER'), ...key }), { mode: 0o600 });
    chmodSync(file, 0o600);
    return { public_key: key.public_key, file };
  },

  // The same statement again: what whoever captured it would send.
  async replay([device = 'a']) {
    const answer = await request('POST', '/inbox/session', { body: loadState(device).statement });
    const { token: _, ...shown } = typeof answer.body === 'object' && answer.body !== null ? answer.body : { said: answer.body };
    return { status: answer.status, ...shown };
  },

  async list([device = 'a', show = 'waiting']) {
    return { tasks: await listed(loadState(device), show) };
  },

  async file([id, n, device = 'a']) {
    const state = loadState(device);
    const { read } = await readOne(state, id);
    const note = read.envelope.files[Number(n)];
    if (!note) throw new Error(`the task names no file ${n}`);
    const { ciphertext } = await ask('GET', `/inbox/tasks/${id}/files/${n}`, { token: state.token });
    const bytes = await openFile(read.contentKey, id, Number(n), note, new Uint8Array(Buffer.from(ciphertext, 'base64')));
    return { name: note.name, content_type: note.content_type, size: bytes.length, sha256: note.sha256, starts: Buffer.from(bytes.slice(0, 16)).toString('utf8') };
  },

  // What of the proof is checked without the quote verifier: the run, the
  // answer against the attested hash, and the task named in the answer. The
  // quote itself is the dashboard's to verify (`lib/attestation-verify`).
  async proof([id, device = 'a']) {
    const state = loadState(device);
    const { task, read } = await readOne(state, id);
    const origin = await ask('GET', `/inbox/tasks/${id}/origin`, { token: state.token });
    const where = origin.door === 'https' ? `by-call/${origin.call_id}` : `by-request/${origin.request_id}`;
    const found = await request('GET', `/attestations/${where}`);
    if (found.status === 404) return { run: origin.run, door: origin.door, attested: false };
    if (found.status !== 200) throw new Error(`the attestation answered ${found.status}`);
    const attestation = found.body;
    const out = {
      run: origin.run,
      door: origin.door,
      attested: true,
      job: attestation.task_id,
      project_matches: attestation.project_id === task.project_id,
      build: attestation.executed_wasm_sha256 ?? null,
      output_kept: origin.output !== null,
      answer_matches: null,
      names_task: null,
    };
    if (origin.output !== null) {
      const digest = toHex(new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(origin.output))));
      out.answer_matches = digest === attestation.output_hash;
      out.names_task = namesTask(origin.output, id, read.hash);
      out.names_another_hash = namesTask(origin.output, id, '0'.repeat(64));
    }
    return out;
  },

  async seal([id, purpose, text, device = 'a']) {
    if (purpose !== Purpose.Answer && purpose !== Purpose.Rejection) throw new Error('the purpose is `answer` or `rejection`');
    const { read } = await readOne(loadState(device), id);
    return { sealed: Buffer.from(await writeReply(read.envelope, purpose, text)).toString('base64') };
  },

  async reject([id, text = '', device = 'a']) {
    const state = loadState(device);
    let reason = null;
    if (text) {
      const { read } = await readOne(state, id);
      reason = Buffer.from(await writeReply(read.envelope, Purpose.Rejection, text)).toString('base64');
    }
    return request('POST', `/inbox/tasks/${id}/reject`, { token: state.token, body: { reason } });
  },

  async delete([id, device = 'a']) {
    return request('DELETE', `/inbox/tasks/${id}`, { token: loadState(device).token });
  },

  async mute([subject_is, subject, device = 'a']) {
    return request('POST', '/inbox/mutes', { token: loadState(device).token, body: { subject_is, subject, delete_waiting: true } });
  },

  async unmute([subject_is, subject, device = 'a']) {
    return request('DELETE', '/inbox/mutes', { token: loadState(device).token, body: { subject_is, subject } });
  },

  async devices([device = 'a']) {
    const state = loadState(device);
    const answer = await request('GET', '/inbox/devices', { token: state.token });
    const devices = Array.isArray(answer.body?.devices) ? answer.body.devices : [];
    const here = devices.filter((d) => d.this === true);
    return {
      status: answer.status,
      reason: answer.body?.reason ?? null,
      count: devices.length,
      marked_this: here.length,
      this_is_this_device: here.length === 1 && here[0].id === state.device_id && here[0].device_pubkey === state.pubkey,
      signer_pubkey: here.length === 1 ? here[0].signer_pubkey : null,
      // The other devices' ids, for withdrawing one.
      others: devices.filter((d) => d.this !== true).map((d) => d.id),
    };
  },

  async webhook([action = 'get', ...rest]) {
    if (action === 'set') {
      const [variable = '', device = 'a', signed = 'signed'] = rest;
      const url = need(variable);
      // `unsigned`: the request without the owner's confirmation, to see it refused.
      const body = signed === 'unsigned' ? { url } : { url, confirmation: await confirmed({ name_webhook: url }) };
      return webhookShown(await request('PUT', '/inbox/webhook', { token: loadState(device).token, body }), url);
    }
    if (action === 'get') {
      const [device = 'a', variable = ''] = rest;
      const answer = await request('GET', '/inbox/webhook', { token: loadState(device).token });
      return webhookShown(answer, variable ? need(variable) : undefined);
    }
    if (action === 'delete') {
      const [device = 'a', signed = 'signed'] = rest;
      const body = signed === 'unsigned' ? undefined : { confirmation: await confirmed({ remove_webhook: true }) };
      return webhookShown(await request('DELETE', '/inbox/webhook', { token: loadState(device).token, body }));
    }
    throw new Error('a webhook is asked for with `get`, `set` or `delete`');
  },

  /** Withdraw another device by its id, signed for; `unsigned` sends no confirmation. */
  async withdraw([id = '', device = 'a', signed = 'signed']) {
    if (!id) throw new Error('withdraw takes the id of the device to withdraw');
    const body = signed === 'unsigned' ? undefined : { confirmation: await confirmed({ withdraw_device: id }) };
    const answer = await request('DELETE', `/inbox/devices/${encodeURIComponent(id)}`, { token: loadState(device).token, body });
    return { status: answer.status, ...(typeof answer.body === 'object' && answer.body !== null ? answer.body : {}) };
  },

  async 'sign-out'([device = 'a']) {
    const answer = await request('DELETE', '/inbox/session', { token: loadState(device).token });
    return answer;
  },

  // A session's token in another browser: it lists, and opens nothing.
  async 'copy-token'([from = 'a', to = 'stolen']) {
    const made = await makeDevice();
    saveState(to, { ...made, token: loadState(from).token, device_id: null, statement: null });
    return { copied: true };
  },

  async raw([method, path, body = '', device = 'none']) {
    return request(method, path, { token: tokenOf(device), body: body === '' ? undefined : body });
  },

  // The same request until the limiter answers. Eight at once, so that the
  // limit is reached inside the limiter's own window on a slow line too.
  async flood([count = '', path = '/inbox/tasks', device = 'none']) {
    const most = Number(count);
    if (!Number.isInteger(most) || most < 1 || most > 1000) throw new Error('`count` is from 1 to 1000');
    const token = tokenOf(device);
    const statuses = {};
    let sent = 0;
    let limited = null;
    while (sent < most && limited === null) {
      const together = Math.min(8, most - sent);
      const answers = await Promise.all(Array.from({ length: together }, () => request('GET', path, { token })));
      for (const answer of answers) {
        sent += 1;
        statuses[answer.status] = (statuses[answer.status] ?? 0) + 1;
        if (answer.status === 429 && limited === null) {
          const said = typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body);
          limited = {
            said: said.slice(0, 300),
            names_a_number: /[0-9]/.test(said),
            retry_after: answer.retry_after,
            headers_of_a_limit: answer.limit_headers,
          };
        }
      }
    }
    return { sent, statuses, limited };
  },

  async forget() {
    rmSync(need('STATE_DIR'), { recursive: true, force: true });
    return { forgotten: true };
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
