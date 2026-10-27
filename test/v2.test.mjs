import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  MAX_PASSKEYS, VaultError, addPasskey, createPrfBinding, openWithPrf, openWithRecovery,
  parseVault, requestPrf, seal, serializeVault, validateVault, vaultBindings,
} from '../dist/index.js';
import { createReferenceFixtureV2, openReference } from './reference.mjs';

const fixture = JSON.parse(await readFile(new URL('../examples/v2-fixture.json', import.meta.url), 'utf8'));
const v1Fixture = JSON.parse(await readFile(new URL('../examples/v1-fixture.json', import.meta.url), 'utf8'));
const plain = Buffer.from(fixture.plaintext, 'base64url');
const fromBase64 = value => new Uint8Array(Buffer.from(value, 'base64url'));
const secret = fill => new Uint8Array(32).fill(fill);
const isCode = code => error => error instanceof VaultError && error.code === code;
const primary = createPrfBinding('AQID', 'example.com');
const withId = credentialId => ({ ...primary, credentialId });

async function twoPasskeys() {
  const { vault, recoveryKey } = await seal(new Uint8Array([1, 2, 3]), { binding: primary, prfOutput: secret(1) });
  const upgraded = await addPasskey(vault, { prfOutput: secret(1) }, { binding: withId('BAUG'), prfOutput: secret(2) });
  return { vault, upgraded, recoveryKey };
}

test('persisted v2 fixture is reproducible and opens with every passkey and recovery', async () => {
  assert.deepEqual(createReferenceFixtureV2(), fixture);
  for (const { prfOutput } of fixture.prfOutputs) {
    assert.deepEqual(Buffer.from(await openWithPrf(structuredClone(fixture.vault), fromBase64(prfOutput))), plain);
  }
  assert.deepEqual(Buffer.from(await openWithRecovery(structuredClone(fixture.vault), fixture.recoveryKey)), plain);
  assert.deepEqual(vaultBindings(fixture.vault).map(binding => binding.credentialId),
    fixture.prfOutputs.map(item => item.credentialId));
  assert.equal(serializeVault(parseVault(JSON.stringify(fixture.vault))), JSON.stringify(fixture.vault));
});

test('addPasskey preserves existing slots and the independent reader opens the result', async () => {
  const { vault, upgraded, recoveryKey } = await twoPasskeys();
  assert.equal(upgraded.version, 2);
  assert.deepEqual(Object.keys(upgraded),
    ['version', 'suite', 'id', 'hkdfSalt', 'binding', 'passkey', 'extraPasskeys', 'recovery', 'payload']);
  assert.deepEqual([upgraded.passkey, upgraded.recovery], [vault.passkey, vault.recovery]);
  assert.notEqual(upgraded.payload.iv, vault.payload.iv);
  for (const [credentialId, fill] of [['AQID', 1], ['BAUG', 2]]) {
    assert.deepEqual(openReference(upgraded, Buffer.from(secret(fill)), 'passkey', credentialId), Buffer.from([1, 2, 3]));
    assert.deepEqual(await openWithPrf(upgraded, secret(fill)), new Uint8Array([1, 2, 3]));
  }
  assert.deepEqual(openReference(upgraded, Buffer.from(recoveryKey, 'base64url'), 'recovery'), Buffer.from([1, 2, 3]));
});

test('addPasskey accepts the recovery key, upgrades the v1 fixture and leaves caller buffers intact', async () => {
  const { upgraded, recoveryKey } = await twoPasskeys();
  const added = secret(3);
  const third = await addPasskey(upgraded, { recoveryKey }, { binding: withId('BwgJ'), prfOutput: added });
  assert.deepEqual(added, secret(3));
  assert.deepEqual(await openWithPrf(third, secret(3)), new Uint8Array([1, 2, 3]));
  const fixtureBinding = { ...v1Fixture.vault.binding, credentialId: 'CgsM' };
  const unlock = fromBase64(v1Fixture.prfOutput);
  const fromV1 = await addPasskey(v1Fixture.vault, { prfOutput: unlock }, { binding: fixtureBinding, prfOutput: secret(4) });
  assert.deepEqual(unlock, fromBase64(v1Fixture.prfOutput));
  assert.deepEqual(Buffer.from(await openWithPrf(fromV1, secret(4))), Buffer.from(v1Fixture.plaintext, 'base64url'));
});

test('addPasskey rejects mismatched, duplicate, enrolled and excess passkeys', async () => {
  const { upgraded, recoveryKey } = await twoPasskeys();
  const cases = [
    [{ prfOutput: secret(1) }, withId('BAUG'), secret(5)],
    [{ prfOutput: secret(1) }, { ...withId('DQ4P'), rpId: 'other.example' }, secret(5)],
    [{ prfOutput: secret(1) }, createPrfBinding('DQ4P', 'example.com'), secret(5)],
    [{ prfOutput: secret(1), recoveryKey }, withId('DQ4P'), secret(5)],
    [{}, withId('DQ4P'), secret(5)],
    [{ prfOutput: secret(1) }, withId('DQ4P'), secret(2)],
  ];
  for (const [unlockWith, binding, prfOutput] of cases) {
    await assert.rejects(addPasskey(upgraded, unlockWith, { binding, prfOutput }), isCode('INVALID_INPUT'));
  }
  await assert.rejects(addPasskey(upgraded, { prfOutput: secret(9) }, { binding: withId('DQ4P'), prfOutput: secret(5) }),
    isCode('UNLOCK_FAILED'));
  let full = upgraded;
  for (let index = 3; index <= MAX_PASSKEYS; index += 1) {
    full = await addPasskey(full, { recoveryKey }, { binding: withId(Buffer.from([200, index]).toString('base64url')), prfOutput: secret(index + 10) });
  }
  assert.equal(vaultBindings(full).length, MAX_PASSKEYS);
  await assert.rejects(addPasskey(full, { recoveryKey }, { binding: withId('DQ4P'), prfOutput: secret(99) }), isCode('INVALID_INPUT'));
});

test('slot removal, reordering and substitution fail payload authentication', async () => {
  const edits = [
    vault => { vault.extraPasskeys.pop(); },
    vault => { vault.extraPasskeys.reverse(); },
    vault => {
      [vault.binding, vault.passkey, vault.extraPasskeys[0].binding, vault.extraPasskeys[0].passkey] =
        [vault.extraPasskeys[0].binding, vault.extraPasskeys[0].passkey, vault.binding, vault.passkey];
    },
  ];
  for (const edit of edits) {
    const vault = structuredClone(fixture.vault);
    edit(vault);
    await assert.rejects(openWithRecovery(vault, fixture.recoveryKey), isCode('UNLOCK_FAILED'));
    await assert.rejects(openWithPrf(vault, fromBase64(fixture.prfOutputs[0].prfOutput)), isCode('UNLOCK_FAILED'));
  }
});

test('malformed v2 structure and unknown versions have explicit codes', () => {
  const variants = [
    vault => { vault.version = 1; },
    vault => { vault.extraPasskeys = []; },
    vault => { delete vault.extraPasskeys; },
    vault => { vault.extraPasskeys[0].binding.prfSalt = primary.prfSalt; },
    vault => { vault.extraPasskeys[0].binding.credentialId = vault.binding.credentialId; },
    vault => { vault.extraPasskeys = new Array(1); },
    vault => { vault.extraPasskeys.push(...Array.from({ length: MAX_PASSKEYS }, () => vault.extraPasskeys[0])); },
    vault => { Object.defineProperty(vault.extraPasskeys, 0, { get() { throw new Error('ran'); }, enumerable: true }); },
  ];
  for (const edit of variants) {
    const vault = structuredClone(fixture.vault);
    edit(vault);
    assert.throws(() => validateVault(vault), isCode('INVALID_ENVELOPE'));
  }
  assert.throws(() => validateVault({ ...fixture.vault, version: 3, futureField: true }), isCode('UNSUPPORTED_VERSION'));
});

test('requestPrf offers every slot credential with the shared PRF input', async t => {
  const requests = [];
  let rawId = Buffer.from('KSorLC0uLzA', 'base64url');
  class Credential {
    constructor(id) { this.rawId = new Uint8Array(id).buffer; }
    getClientExtensionResults() { return { prf: { results: { first: secret(7).buffer } } }; }
  }
  for (const [name, value] of [['isSecureContext', true], ['PublicKeyCredential', Credential],
    ['navigator', { credentials: { get: async options => { requests.push(options); return new Credential(rawId); } } }]]) {
    const original = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { configurable: true, value });
    t.after(() => original ? Object.defineProperty(globalThis, name, original) : delete globalThis[name]);
  }
  const bindings = vaultBindings(fixture.vault);
  assert.deepEqual(await requestPrf(bindings), secret(7));
  const { publicKey } = requests[0];
  assert.deepEqual(publicKey.allowCredentials.map(item => Buffer.from(item.id).toString('base64url')),
    bindings.map(binding => binding.credentialId));
  assert.equal(Buffer.from(publicKey.extensions.prf.eval.first).toString('base64url'), bindings[0].prfSalt);
  assert.equal(publicKey.userVerification, 'required');
  rawId = Buffer.from([9, 9, 9]);
  await assert.rejects(requestPrf(bindings), isCode('WEBAUTHN_FAILED'));
  const { proxy, revoke } = Proxy.revocable([], {});
  revoke();
  for (const invalid of [[], [primary, primary], [primary, createPrfBinding('BAUG', 'example.com')], proxy,
    Array.from({ length: MAX_PASSKEYS + 1 }, (_, index) => withId(Buffer.from([index + 1]).toString('base64url')))]) {
    await assert.rejects(requestPrf(invalid), isCode('INVALID_INPUT'));
  }
});
