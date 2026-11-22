// Seals bytes to a component's encryption public key, as a client does:
// `0x02 || ephemeral X25519 public key || AES-256-GCM(ciphertext || tag)`,
// the format `open` reads (worker/wit/deps/encryption-keys.wit). WebCrypto
// only; Node 20+.
//
//   node seal_to.mjs <public_key_hex> <plaintext_hex> [aad_hex]   → sealed, hex
//   node seal_to.mjs --self-test                                  → checks the worker's vector

const INFO = new TextEncoder().encode('outlayer:encryption-keys:v1:seal:kdf');
const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const toHex = (bytes) => Buffer.from(bytes).toString('hex');
const subtle = globalThis.crypto.subtle;

async function sealWith(ephemeral, recipientRaw, plaintext, aad) {
  const recipient = await subtle.importKey('raw', recipientRaw, { name: 'X25519' }, false, []);
  const ephemeralPublic = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey));
  const shared = await subtle.deriveBits({ name: 'X25519', public: recipient }, ephemeral.privateKey, 256);
  const hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const info = Buffer.concat([INFO, ephemeralPublic, recipientRaw]);
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const sealed = await subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12), additionalData: aad }, key, plaintext);
  return Buffer.concat([Buffer.from([0x02]), ephemeralPublic, Buffer.from(sealed)]);
}

async function pairOf(secret) {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), secret]);
  const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
  const { x } = await subtle.exportKey('jwk', privateKey);
  const publicKey = await subtle.importKey('jwk', { kty: 'OKP', crv: 'X25519', x }, { name: 'X25519' }, true, []);
  return { privateKey, publicKey };
}

const [first, plaintextHex = '', aadHex = ''] = process.argv.slice(2);
if (first === '--self-test') {
  // worker/src/encryption_keys/mod.rs, `the_golden_sealed_message_opens`.
  const sealed = await sealWith(
    await pairOf(Buffer.alloc(32, 1)),
    fromHex('d8dab3938ebf11fb0a976ee6464fca1dd8ae1ae2c089eb74f242b8785deead69'),
    Buffer.from('{"q":"hello"}'),
    Buffer.from('outlayer-input'),
  );
  const golden =
    '02a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a20982e4d1d0f68949731b656844b619291fe1168ba3cbfbff8e236533ad1d';
  if (toHex(sealed) !== golden) {
    console.error(`self-test FAILED: ${toHex(sealed)}`);
    process.exit(1);
  }
  console.log('ok');
} else {
  const recipient = fromHex(first ?? '');
  if (recipient.length !== 32) {
    console.error('usage: seal_to.mjs <public_key_hex (32 bytes)> <plaintext_hex> [aad_hex]');
    process.exit(2);
  }
  const ephemeral = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  process.stdout.write(toHex(await sealWith(ephemeral, recipient, fromHex(plaintextHex), fromHex(aadHex))));
}
