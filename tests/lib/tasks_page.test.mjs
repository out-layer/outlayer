// node --test tests/lib/tasks_page.test.mjs
//
// The page's side of a task against the host's: the vectors here are pinned
// in `worker/src/tasks/crypto.rs` (`the_golden_vectors_the_page_also_opens`),
// which made them. Change one side and the other must move.

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  Purpose, approval, fromBase58, fromHex, newDevice, openContent, openFrom, readPubkey, readTask, sealTo, signApproval,
  signStatement, statement, supplyDigest, toBase58, toHex, writePubkey,
} from './tasks_page.mjs';

const subtle = globalThis.crypto.subtle;

// The device of the golden vectors: the scalar 01 02 … 20, imported so that
// it cannot be exported — as a device's key is.
const GOLDEN_DEVICE_PKCS8 =
  '308141020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420' +
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
const GOLDEN = JSON.parse(process.env.TASKS_GOLDEN ?? 'null') ?? (await import('./tasks_golden.json', { with: { type: 'json' } })).default;

async function goldenDevice() {
  const privateKey = await subtle.importKey(
    'pkcs8', fromHex(GOLDEN_DEVICE_PKCS8), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
  );
  return { privateKey, point: readPubkey(GOLDEN.device_pubkey), pubkey: GOLDEN.device_pubkey };
}

test('a device key cannot be exported by the page', async () => {
  const device = await newDevice();
  assert.equal(device.privateKey.extractable, false);
  for (const format of ['pkcs8', 'jwk', 'raw']) {
    await assert.rejects(subtle.exportKey(format, device.privateKey));
  }
  assert.equal(readPubkey(device.pubkey).length, 65);
  assert.equal(writePubkey(device.point), device.pubkey);
});

test('the sentence is the one the host and the coordinator rebuild', () => {
  assert.equal(
    statement('alice.near', 'p256:abc', 1793275200),
    'Sign in to OutLayer as alice.near. Device key: p256:abc. Valid until 2026-10-29T12:00:00Z.',
  );
});

// Pinned in the coordinator's `confirmation.rs` and the worker's `statement.rs`:
// the same sentence, the same digest vectors.
test('the approval is one sentence, and its digest is of one canonical document', async () => {
  const ID = '0b9c1a52-7c1e-4a53-9c58-2f0c8f6f3b11-0';
  const nothing = await supplyDigest(null, null);
  assert.equal(nothing, '93121736c33115cb57757d3d5c09b430c4a03d2c3fa06dbbda48a466620b5799');
  assert.equal(
    approval('alice.near', ID, 'ab'.repeat(32), nothing, 1793275200),
    `Approve in OutLayer as alice.near: task ${ID} with hash ${'ab'.repeat(32)} and supply ${nothing}. At 2026-10-29T12:00:00Z.`,
  );
  const of = async (text) => toHex(new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(text))));
  assert.equal(await supplyDigest('YWJj', null), await of('{"note":null,"supplied":"YWJj"}'));
  assert.equal(await supplyDigest('YWJj', 'aGk='), await of('{"note":"aGk=","supplied":"YWJj"}'));
  assert.equal(await supplyDigest(null, 'aGk='), await of('{"note":"aGk=","supplied":null}'));
  assert.notEqual(await supplyDigest('YWJj', null), await supplyDigest(null, 'YWJj'), 'a note is not a supply');
  const signed = await signApproval({
    account: 'owner.testnet',
    secretKey: `ed25519:${toBase58(new Uint8Array(32).fill(1))}`,
    id: ID,
    hash: 'ab'.repeat(32),
    supplied: null,
    note: null,
    at: 1793275200,
    nonce: new Uint8Array(32).fill(3),
    recipient: 'outlayer.testnet',
  });
  if (process.env.TASKS_PRINT) console.log(`APPROVAL_FROM_THE_PAGE = ${JSON.stringify(signed)}`);
  assert.deepEqual(Object.keys(signed).sort(), ['at', 'nonce', 'public_key', 'signature']);
  assert.equal(signed.public_key, 'ed25519:AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9');
  assert.equal(Buffer.from(signed.signature, 'base64').length, 64);
  // A note is sealed under its own purpose, and opens under no other.
  const reader = await newDevice();
  const sealed = await sealTo(reader.point, Purpose.Note, 'run-7', new TextEncoder().encode('go ahead'));
  assert.equal(new TextDecoder().decode(await openFrom(reader.privateKey, reader.point, Purpose.Note, 'run-7', sealed)), 'go ahead');
  await assert.rejects(openFrom(reader.privateKey, reader.point, Purpose.Answer, 'run-7', sealed));
});

test('what the host made for the device, the page opens', async () => {
  const device = await goldenDevice();
  const key = await openFrom(device.privateKey, device.point, Purpose.DeviceCopy, GOLDEN.task, fromHex(GOLDEN.device_copy));
  assert.equal(toHex(key), GOLDEN.content_key);
  const document = await openContent(key, GOLDEN.task, fromHex(GOLDEN.content));
  assert.equal(new TextDecoder().decode(document), GOLDEN.document);

  const read = await readTask(device, {
    id: GOLDEN.task,
    device_copy: Buffer.from(fromHex(GOLDEN.device_copy)).toString('base64'),
    content: Buffer.from(fromHex(GOLDEN.content)).toString('base64'),
  });
  assert.equal(read.hash, GOLDEN.hash);
  assert.equal(read.envelope.display.title, 'Send an email');
});

test('a copy opens for its device, its purpose and its task, and for nothing else', async () => {
  const device = await goldenDevice();
  const copy = fromHex(GOLDEN.device_copy);
  const other = await newDevice();
  await assert.rejects(openFrom(other.privateKey, other.point, Purpose.DeviceCopy, GOLDEN.task, copy), /decryption failed/);
  await assert.rejects(openFrom(device.privateKey, device.point, Purpose.Answer, GOLDEN.task, copy), /decryption failed/);
  await assert.rejects(openFrom(device.privateKey, device.point, Purpose.DeviceCopy, 'run-1', copy), /decryption failed/);
  await assert.rejects(openFrom(device.privateKey, device.point, Purpose.DeviceCopy, GOLDEN.task, copy.slice(0, -1)), /decryption failed/);
  const key = fromHex(GOLDEN.content_key);
  await assert.rejects(openContent(key, 'run-1', fromHex(GOLDEN.content)), /decryption failed/);
  await assert.rejects(
    readTask(device, { id: 'run-1', device_copy: Buffer.from(copy).toString('base64'), content: '' }),
    /decryption failed/,
  );
  await assert.rejects(readTask(device, { id: GOLDEN.task, device_copy: null, content: '' }), /locked/);
});

test('what the page seals, a key of its own kind opens', async () => {
  const recipient = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const point = new Uint8Array(await subtle.exportKey('raw', recipient.publicKey));
  const blob = await sealTo(point, Purpose.Answer, 'run-0', new TextEncoder().encode('ipfs://photo'));
  assert.equal(blob.length, 1 + 65 + 12 + 12 + 16);
  const opened = await openFrom(recipient.privateKey, point, Purpose.Answer, 'run-0', blob);
  assert.equal(new TextDecoder().decode(opened), 'ipfs://photo');
});

// Printed for `worker/src/tasks/crypto.rs` to pin: an answer sealed by the
// page to the golden task's reply key.
test('an answer for the host to open', async () => {
  const blob = await sealTo(readPubkey(GOLDEN.reply_pubkey), Purpose.Answer, GOLDEN.task, new TextEncoder().encode('ipfs://photo#sha256=abc'));
  if (process.env.TASKS_PRINT) console.log(`ANSWER_FROM_THE_PAGE = ${toHex(blob)}`);
  assert.equal(blob[0], 0x01);
});

// Pinned in `worker/src/tasks/statement.rs` (`the_statement_the_page_signs_holds`):
// the wallet key of seed 01 01 … 01, the golden device, a fixed nonce.
test('a statement signed here is the one the host checks', async () => {
  const seed = new Uint8Array(32).fill(1);
  const signed = await signStatement({
    account: 'owner.testnet',
    secretKey: `ed25519:${toBase58(seed)}`,
    devicePubkey: GOLDEN.device_pubkey,
    validUntil: 4000000000,
    nonce: new Uint8Array(32).fill(3),
    recipient: 'outlayer.testnet',
  });
  if (process.env.TASKS_PRINT) console.log(`STATEMENT_FROM_THE_PAGE = ${JSON.stringify(signed)}`);
  assert.equal(signed.public_key, 'ed25519:AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9');
  assert.equal(Buffer.from(signed.signature, 'base64').length, 64);
  assert.deepEqual(fromBase58(toBase58(new Uint8Array([0, 0, 1, 2, 255]))), new Uint8Array([0, 0, 1, 2, 255]));
});
