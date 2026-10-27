import assert from 'node:assert/strict';
import test from 'node:test';
import { createPrfBinding, requestPrf, seal, VaultError } from '../dist/index.js';

const binding = createPrfBinding('AQID', 'EXAMPLE.com');
const expected = new Uint8Array(32).fill(42);
const isCode = code => error => error instanceof VaultError && error.code === code &&
  error.message === code && !Object.hasOwn(error, 'cause');

function replace(t, name, value) {
  const original = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, { configurable: true, value });
  t.after(() => {
    if (original) Object.defineProperty(globalThis, name, original);
    else delete globalThis[name];
  });
}

function provider(t, get) {
  class Credential {
    constructor(rawId = new Uint8Array([1, 2, 3]).buffer, result = expected.buffer) {
      this.rawId = rawId;
      this.result = result;
    }
    getClientExtensionResults() {
      return this.result === undefined ? {} : { prf: { results: { first: this.result } } };
    }
  }
  replace(t, 'isSecureContext', true);
  replace(t, 'PublicKeyCredential', Credential);
  replace(t, 'navigator', { credentials: { get: options => get(options, Credential) } });
  return Credential;
}

test('requestPrf binds saved RP ID, credential and seed, requires UV and uses fresh challenges', async t => {
  const requests = [];
  provider(t, (options, Credential) => { requests.push(options); return new Credential(); });
  const signal = new AbortController().signal;
  const result = await requestPrf(binding, { timeoutMs: 5000, signal });
  await requestPrf(binding);
  assert.deepEqual(result, expected);
  assert.notEqual(result.buffer, expected.buffer);
  assert.equal(requests[0].signal, signal);
  assert.equal(requests[0].publicKey.timeout, 5000);
  assert.equal(requests[1].publicKey.timeout, 60000);
  for (const { publicKey } of requests) {
    assert.equal(publicKey.rpId, 'example.com');
    assert.equal(publicKey.userVerification, 'required');
    assert.equal(publicKey.challenge.byteLength, 32);
    assert.deepEqual(new Uint8Array(publicKey.allowCredentials[0].id), new Uint8Array([1, 2, 3]));
    assert.equal(publicKey.allowCredentials[0].type, 'public-key');
    assert.equal(Buffer.from(publicKey.extensions.prf.eval.first).toString('base64url'), binding.prfSalt);
  }
  assert.notDeepEqual(requests[0].publicKey.challenge, requests[1].publicKey.challenge);
});

test('PRF typed-array views are copied using their exact byte offset', async t => {
  const backing = new Uint8Array(40).fill(99);
  backing.set(expected, 4);
  provider(t, (_, Credential) => new Credential(undefined, backing.subarray(4, 36)));
  const output = await requestPrf(binding);
  backing.fill(0);
  assert.deepEqual(output, expected);
});

test('unsupported and insecure contexts fail without requesting credentials', async t => {
  let calls = 0;
  provider(t, () => { calls++; throw new Error('unexpected'); });
  Object.defineProperty(globalThis, 'isSecureContext', { configurable: true, value: false });
  await assert.rejects(requestPrf(binding), isCode('WEBAUTHN_UNAVAILABLE'));
  Object.defineProperty(globalThis, 'isSecureContext', { configurable: true, value: true });
  Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, value: undefined });
  await assert.rejects(requestPrf(binding), isCode('WEBAUTHN_UNAVAILABLE'));
  assert.equal(calls, 0);
});

test('invalid options and malformed signals reject before the credential API', async t => {
  let calls = 0;
  provider(t, () => { calls++; return null; });
  for (const options of [null, [], new Date(), { timeoutMs: null }, { timeoutMs: 999 }, { timeoutMs: 120001 }, { timeoutMs: 1000.5 },
    { timeoutMs: Number.NaN }, { signal: {} }, { signal: { aborted: true } }, { signal: true }, { unknown: true }]) {
    await assert.rejects(requestPrf(binding, options), isCode('INVALID_INPUT'));
  }
  assert.equal(calls, 0);
});

test('request options reject accessors and redact reflection failures', async t => {
  let invoked = false;
  let calls = 0;
  provider(t, () => { calls++; return null; });
  const options = {};
  Object.defineProperty(options, 'timeoutMs', { enumerable: true, get() { invoked = true; throw new Error('private-option'); } });
  await assert.rejects(requestPrf(binding, options), isCode('INVALID_INPUT'));
  assert.equal(invoked, false);
  const proxy = new Proxy({}, { getPrototypeOf() { throw new Error('private-proxy'); } });
  await assert.rejects(requestPrf(binding, proxy), isCode('INVALID_INPUT'));
  assert.equal(calls, 0);
});

test('already-aborted signals expose neither their reason nor a credential operation', async t => {
  let calls = 0;
  provider(t, () => { calls++; return null; });
  const controller = new AbortController();
  controller.abort(new Error('private-abort-reason'));
  await assert.rejects(requestPrf(binding, { signal: controller.signal }), isCode('ABORTED'));
  assert.equal(calls, 0);
});

test('in-flight cancellation is classified without forwarding provider or signal errors', async t => {
  const controller = new AbortController();
  provider(t, () => { controller.abort('private-reason'); throw new Error('private-provider-data'); });
  await assert.rejects(requestPrf(binding, { signal: controller.signal }), isCode('ABORTED'));
});

test('cancellation racing with a completed provider discards its secret', async t => {
  const controller = new AbortController();
  provider(t, (_, Credential) => { controller.abort('private-reason'); return new Credential(); });
  await assert.rejects(requestPrf(binding, { signal: controller.signal }), isCode('ABORTED'));
});

test('dismissal and provider failures return stable codes without exception details', async t => {
  provider(t, () => { throw new Error('private-provider-data'); });
  await assert.rejects(requestPrf(binding), isCode('WEBAUTHN_FAILED'));
});

test('null and mismatched credentials cannot return a PRF output', async t => {
  let answer;
  const Credential = provider(t, () => answer);
  for (const value of [null, {}, new Credential(new Uint8Array([9]).buffer)]) {
    answer = value;
    await assert.rejects(requestPrf(binding), isCode('WEBAUTHN_FAILED'));
  }
});

test('missing or incorrectly sized PRF results never downgrade the operation', async t => {
  let result;
  const Credential = provider(t, () => {
    const credential = new Credential();
    credential.result = result;
    return credential;
  });
  for (const value of [undefined, null, new ArrayBuffer(0), new ArrayBuffer(31), new ArrayBuffer(33)]) {
    result = value;
    await assert.rejects(requestPrf(binding), isCode('PRF_UNAVAILABLE'));
  }
  assert.ok(Credential);
});

test('missing native crypto is an explicit failure for binding creation and sealing', async t => {
  replace(t, 'crypto', undefined);
  assert.throws(() => createPrfBinding('AQ', 'example.com'), isCode('CRYPTO_UNAVAILABLE'));
  await assert.rejects(seal(new Uint8Array(), { binding, prfOutput: new Uint8Array(32) }), isCode('CRYPTO_UNAVAILABLE'));
});

test('native encryption exceptions are redacted and caller buffers are preserved', async t => {
  const native = globalThis.crypto;
  replace(t, 'crypto', { subtle: native.subtle, getRandomValues() { throw new Error('private-native-data'); } });
  const secret = new Uint8Array(32).fill(7);
  const plaintext = new Uint8Array([1, 2]);
  await assert.rejects(seal(plaintext, { binding, prfOutput: secret }), isCode('ENCRYPTION_FAILED'));
  assert.deepEqual(secret, new Uint8Array(32).fill(7));
  assert.deepEqual(plaintext, new Uint8Array([1, 2]));
});
