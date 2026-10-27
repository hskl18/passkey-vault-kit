import assert from 'node:assert/strict';
import { hkdfSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  MAX_PLAINTEXT_BYTES, MAX_SERIALIZED_VAULT_CHARS, VaultError, createPrfBinding,
  openWithPrf, openWithRecovery, parseVault, seal, serializeVault, validateVault,
} from '../dist/index.js';
import { createReferenceFixture, openReference } from './reference.mjs';

const fixture = JSON.parse(await readFile(new URL('../examples/v1-fixture.json', import.meta.url), 'utf8'));
const plain = Buffer.from(fixture.plaintext, 'base64url');
const prf = () => new Uint8Array(Buffer.from(fixture.prfOutput, 'base64url'));
const fresh = () => structuredClone(fixture.vault);
const isCode = code => error => error instanceof VaultError && error.code === code &&
  error.message === code && !Object.hasOwn(error, 'cause');
const flip = value => {
  const bytes = Buffer.from(value, 'base64url');
  bytes[0] ^= 1;
  return bytes.toString('base64url');
};

test('independent HKDF oracle agrees with RFC 5869 Appendix A.1', () => {
  const result = hkdfSync('sha256', Buffer.alloc(22, 0x0b),
    Buffer.from('000102030405060708090a0b0c', 'hex'), Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42);
  assert.equal(Buffer.from(result).toString('hex'),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('persisted v1 fixture remains byte-for-byte reproducible', () => {
  assert.deepEqual(createReferenceFixture(), fixture);
});

test('WebCrypto opens independent persisted v1 ciphertext with both secrets', async () => {
  assert.deepEqual(Buffer.from(await openWithPrf(fresh(), prf())), plain);
  assert.deepEqual(Buffer.from(await openWithRecovery(fresh(), fixture.recoveryKey)), plain);
});

test('Node crypto independently opens SDK output with each secret', async () => {
  const input = new Uint8Array([0, 255, 7, 128]);
  const secret = prf();
  const before = structuredClone(fixture.vault.binding);
  const { vault, recoveryKey } = await seal(input, { binding: before, prfOutput: secret });
  assert.deepEqual(openReference(vault, secret, 'passkey'), Buffer.from(input));
  assert.deepEqual(openReference(vault, Buffer.from(recoveryKey, 'base64url'), 'recovery'), Buffer.from(input));
  assert.deepEqual(before, fixture.vault.binding);
  assert.deepEqual(secret, prf());
  assert.deepEqual(input, new Uint8Array([0, 255, 7, 128]));
});

test('seal copies caller buffers and binding before asynchronous work', async () => {
  const input = new Uint8Array([1, 2, 3]);
  const secret = prf();
  const binding = structuredClone(fixture.vault.binding);
  const pending = seal(input, { binding, prfOutput: secret });
  input.fill(9); secret.fill(9); binding.rpId = 'changed.example.com';
  const { vault } = await pending;
  assert.deepEqual(await openWithPrf(vault, prf()), new Uint8Array([1, 2, 3]));
  assert.equal(vault.binding.rpId, 'example.com');
});

test('caller properties cannot disguise native plaintext or secret byte lengths', async () => {
  const oversized = new Uint8Array(MAX_PLAINTEXT_BYTES + 1);
  Object.defineProperty(oversized, 'byteLength', { value: 0 });
  await assert.rejects(seal(oversized, { binding: fixture.vault.binding, prfOutput: prf() }), isCode('INVALID_INPUT'));
  class HiddenLength extends Uint8Array { get byteLength() { return 0; } }
  await assert.rejects(seal(new HiddenLength(MAX_PLAINTEXT_BYTES + 1),
    { binding: fixture.vault.binding, prfOutput: prf() }), isCode('INVALID_INPUT'));

  let getterCalls = 0;
  const input = new Uint8Array([7, 0, 255]);
  const secret = prf();
  for (const value of [input, secret]) Object.defineProperty(value, 'byteLength', {
    get() { getterCalls++; throw new Error('private-length-getter'); },
  });
  const { vault, recoveryKey } = await seal(input, { binding: fixture.vault.binding, prfOutput: secret });
  assert.deepEqual(await openWithRecovery(vault, recoveryKey), new Uint8Array([7, 0, 255]));
  assert.deepEqual(await openWithPrf(vault, secret), new Uint8Array([7, 0, 255]));
  assert.equal(getterCalls, 0);

  const wrong = new Uint8Array(33);
  Object.defineProperty(wrong, 'byteLength', { value: 32 });
  await assert.rejects(seal(input, { binding: fixture.vault.binding, prfOutput: wrong }), isCode('INVALID_INPUT'));
  await assert.rejects(openWithPrf(vault, wrong), isCode('INVALID_INPUT'));
});

test('random keys, salts, envelope IDs and IVs are fresh across seals', async () => {
  const a = await seal(plain, { binding: fixture.vault.binding, prfOutput: prf() });
  const b = await seal(plain, { binding: fixture.vault.binding, prfOutput: prf() });
  assert.notEqual(a.recoveryKey, b.recoveryKey);
  for (const field of ['id', 'hkdfSalt']) assert.notEqual(a.vault[field], b.vault[field]);
  for (const slot of ['passkey', 'recovery', 'payload']) {
    assert.notEqual(a.vault[slot].iv, b.vault[slot].iv);
    assert.notEqual(a.vault[slot].ciphertext, b.vault[slot].ciphertext);
  }
  assert.equal(new Set(['passkey', 'recovery', 'payload'].map(slot => a.vault[slot].iv)).size, 3);
});

test('both unlock methods reject the wrong secret and a secret for the other purpose', async () => {
  await assert.rejects(openWithPrf(fresh(), new Uint8Array(32)), isCode('UNLOCK_FAILED'));
  await assert.rejects(openWithRecovery(fresh(), Buffer.alloc(32).toString('base64url')), isCode('UNLOCK_FAILED'));
  await assert.rejects(openWithPrf(fresh(), new Uint8Array(Buffer.from(fixture.recoveryKey, 'base64url'))), isCode('UNLOCK_FAILED'));
  await assert.rejects(openWithRecovery(fresh(), fixture.prfOutput), isCode('UNLOCK_FAILED'));
});

test('every authenticated header and ciphertext field rejects tampering through both methods', async t => {
  const fields = ['id', 'hkdfSalt', 'binding.credentialId', 'binding.prfSalt',
    'passkey.iv', 'passkey.ciphertext', 'recovery.iv', 'recovery.ciphertext', 'payload.iv', 'payload.ciphertext'];
  for (const path of fields) await t.test(path, async () => {
    const vault = fresh();
    const parts = path.split('.');
    const parent = parts.length === 1 ? vault : vault[parts[0]];
    parent[parts.at(-1)] = flip(parent[parts.at(-1)]);
    await assert.rejects(openWithPrf(vault, prf()), isCode('UNLOCK_FAILED'));
    await assert.rejects(openWithRecovery(vault, fixture.recoveryKey), isCode('UNLOCK_FAILED'));
  });
  const vault = fresh();
  vault.binding.rpId = 'other.example.com';
  await assert.rejects(openWithPrf(vault, prf()), isCode('UNLOCK_FAILED'));
  await assert.rejects(openWithRecovery(vault, fixture.recoveryKey), isCode('UNLOCK_FAILED'));
});

test('wrapped-key swapping and cross-envelope substitution fail authentication', async () => {
  const swapped = fresh();
  [swapped.passkey, swapped.recovery] = [swapped.recovery, swapped.passkey];
  await assert.rejects(openWithPrf(swapped, prf()), isCode('UNLOCK_FAILED'));
  await assert.rejects(openWithRecovery(swapped, fixture.recoveryKey), isCode('UNLOCK_FAILED'));
  const { vault: other } = await seal(plain, { binding: fixture.vault.binding, prfOutput: prf() });
  for (const slot of ['passkey', 'recovery', 'payload']) {
    const vault = fresh(); vault[slot] = other[slot];
    await assert.rejects(openWithPrf(vault, prf()), isCode('UNLOCK_FAILED'));
    await assert.rejects(openWithRecovery(vault, fixture.recoveryKey), isCode('UNLOCK_FAILED'));
  }
});

test('serialization validates, copies nested records and has stable field order', () => {
  const vault = fresh();
  assert.equal(serializeVault(parseVault(serializeVault(vault))), serializeVault(vault));
  const copy = validateVault(vault);
  copy.binding.rpId = 'new.example.com'; copy.passkey.iv = '';
  assert.deepEqual(vault, fixture.vault);
  assert.deepEqual(Object.keys(copy), ['version', 'suite', 'id', 'hkdfSalt', 'binding', 'passkey', 'recovery', 'payload']);
  const nullPrototype = Object.assign(Object.create(null), fresh());
  assert.deepEqual(validateVault(nullPrototype), vault);
});

test('unsupported formats have explicit error codes', () => {
  for (const version of [0, 3, -1]) assert.throws(() => validateVault({ ...fresh(), version }), isCode('UNSUPPORTED_VERSION'));
  assert.throws(() => validateVault({ ...fresh(), version: 2 }), isCode('INVALID_ENVELOPE'));
  assert.throws(() => validateVault({ ...fresh(), suite: 'AES-CBC' }), isCode('UNSUPPORTED_SUITE'));
  for (const version of [1.5, '1', Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateVault({ ...fresh(), version }), isCode('INVALID_ENVELOPE'));
  }
});

test('invalid JSON, extra/missing fields, object prototypes and binary sizes fail', () => {
  for (const value of [null, [], 'x', 4, new Date(), { ...fresh(), extra: true }]) {
    assert.throws(() => validateVault(value), isCode('INVALID_ENVELOPE'));
  }
  for (const path of ['id', 'hkdfSalt', 'binding', 'passkey', 'recovery', 'payload']) {
    const value = fresh(); delete value[path];
    assert.throws(() => validateVault(value), isCode('INVALID_ENVELOPE'));
  }
  for (const value of ['', '{', 'null', '[]', '"hello"', 3, ' '.repeat(MAX_SERIALIZED_VAULT_CHARS + 1)]) {
    assert.throws(() => parseVault(value), isCode('INVALID_ENVELOPE'));
  }
  for (const slot of ['passkey', 'recovery', 'payload']) for (const field of ['iv', 'ciphertext']) {
    const value = fresh(); value[slot][field] = 'AA';
    assert.throws(() => validateVault(value), isCode('INVALID_ENVELOPE'));
  }
});

test('base64url must be canonical, unpadded and bounded', () => {
  const value = fresh();
  const last = value.id.at(-1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const noncanonical = value.id.slice(0, -1) + alphabet[alphabet.indexOf(last) + 1];
  for (const id of [value.id + '=', value.id + '\n', '+'.repeat(22), noncanonical, 'A'.repeat(2000)]) {
    assert.throws(() => validateVault({ ...value, id }), isCode('INVALID_ENVELOPE'));
  }
});

test('RP IDs normalize IDNA and reject URLs, ports, IPs and malformed labels', () => {
  assert.equal(createPrfBinding('AQ', 'EXAMPLE.com').rpId, 'example.com');
  assert.equal(createPrfBinding('AQ', 'b\u00fccher.example').rpId, 'xn--bcher-kva.example');
  assert.equal(createPrfBinding('AQ', 'localhost').rpId, 'localhost');
  const a = createPrfBinding('AQ', 'example.com');
  const b = createPrfBinding('AQ', 'example.com');
  assert.equal(Buffer.from(a.prfSalt, 'base64url').length, 32);
  assert.notEqual(a.prfSalt, b.prfSalt);
  for (const rpId of ['', 'https://example.com', 'example.com:443', 'example.com.', '127.0.0.1',
    '[::1]', '0x7f000001', 'example', '-bad.example', 'bad_.example', 'a'.repeat(64) + '.com',
    'user@example.com', 'example.com/path', 'example.com\\path', ' example.com', '\ud800.example', 'x'.repeat(254)]) {
    assert.throws(() => createPrfBinding('AQ', rpId), isCode('INVALID_INPUT'));
  }
  for (const id of ['', 'A', 'AQ==', 'AR', Buffer.alloc(1025).toString('base64url')]) {
    assert.throws(() => createPrfBinding(id, 'example.com'), isCode('INVALID_INPUT'));
  }
});

test('async input failures reject promises instead of throwing synchronously', async () => {
  for (const input of [null, 'secret', new Uint8Array(31), new Uint8Array(33), new DataView(new ArrayBuffer(32))]) {
    let pending;
    assert.doesNotThrow(() => { pending = openWithPrf(fresh(), input); });
    assert.ok(pending instanceof Promise);
    await assert.rejects(pending, isCode('INVALID_INPUT'));
  }
  for (const recovery of ['', 'secret', null, fixture.recoveryKey + '=']) {
    let pending;
    assert.doesNotThrow(() => { pending = openWithRecovery(fresh(), recovery); });
    await assert.rejects(pending, isCode('INVALID_INPUT'));
  }
  await assert.rejects(seal('not bytes', { binding: fixture.vault.binding, prfOutput: prf() }), isCode('INVALID_INPUT'));
  await assert.rejects(seal(plain, null), isCode('INVALID_INPUT'));
  await assert.rejects(seal(plain, { binding: {}, prfOutput: prf() }), isCode('INVALID_INPUT'));
});

test('empty and maximum payloads round-trip; bytes above the ceiling reject', async () => {
  for (const length of [0, MAX_PLAINTEXT_BYTES]) {
    const input = new Uint8Array(length);
    if (length) input[length - 1] = 255;
    const { vault, recoveryKey } = await seal(input, { binding: fixture.vault.binding, prfOutput: prf() });
    assert.ok(serializeVault(vault).length <= MAX_SERIALIZED_VAULT_CHARS);
    assert.deepEqual(await openWithPrf(vault, prf()), input);
    assert.deepEqual(await openWithRecovery(parseVault(serializeVault(vault)), recoveryKey), input);
  }
  await assert.rejects(seal(new Uint8Array(MAX_PLAINTEXT_BYTES + 1),
    { binding: fixture.vault.binding, prfOutput: prf() }), isCode('INVALID_INPUT'));
});

test('malicious record accessors reject without execution or leaking exceptions', () => {
  let invoked = false;
  const vault = fresh();
  Object.defineProperty(vault, 'id', { enumerable: true, get() { invoked = true; throw new Error('private-secret'); } });
  assert.throws(() => validateVault(vault), isCode('INVALID_ENVELOPE'));
  assert.equal(invoked, false);
});

test('symbols, hidden fields and throwing proxies reject with the public error contract', () => {
  const hidden = fresh(); Object.defineProperty(hidden, 'hidden', { value: 'secret' });
  const symbol = fresh(); symbol[Symbol('hidden')] = true;
  const proxy = new Proxy({}, { getPrototypeOf() { throw new Error('private-secret'); } });
  for (const value of [hidden, symbol, proxy]) assert.throws(() => validateVault(value), isCode('INVALID_ENVELOPE'));
});

test('seal options and byte inputs cannot expose caller-supplied accessors or proxy exceptions', async () => {
  let invoked = false;
  const options = { prfOutput: prf() };
  Object.defineProperty(options, 'binding', { enumerable: true, get() { invoked = true; throw new Error('private-option'); } });
  await assert.rejects(seal(plain, options), isCode('INVALID_INPUT'));
  assert.equal(invoked, false);
  const proxy = new Proxy({}, { getPrototypeOf() { throw new Error('private-proxy'); } });
  await assert.rejects(seal(plain, proxy), isCode('INVALID_INPUT'));
  await assert.rejects(openWithPrf(fresh(), new Proxy(prf(), {})), isCode('INVALID_INPUT'));
  await assert.rejects(seal(new Proxy(plain, {}), { binding: fixture.vault.binding, prfOutput: prf() }), isCode('INVALID_INPUT'));
});
