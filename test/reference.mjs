import { createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';

// Independent Node crypto implementation of FORMAT.md, never imported by the SDK.
const bytes = (length, start) => Buffer.from(Array.from({ length }, (_, i) => (start + i) % 256));
const encoded = value => Buffer.from(value).toString('base64url');
const decoded = value => Buffer.from(value, 'base64url');
const json = value => Buffer.from(JSON.stringify(value));
// Wrapped-key AAD always uses format 1; the payload AAD uses the envelope version.
const base = (v, purpose, version = 1) => ['passkey-vault-kit', version, v.suite, v.id, v.hkdfSalt, purpose];
const bindingFields = binding => [binding.rpId, binding.credentialId, binding.prfSalt];
const wrapAad = (v, purpose, binding = v.binding) =>
  json([...base(v, purpose), ...(purpose === 'passkey' ? bindingFields(binding) : [])]);
const payloadAad = v => json([...base(v, 'payload', v.version), ...bindingFields(v.binding),
  v.passkey.iv, v.passkey.ciphertext, v.recovery.iv, v.recovery.ciphertext,
  ...(v.extraPasskeys ?? []).flatMap(slot => [...bindingFields(slot.binding), slot.passkey.iv, slot.passkey.ciphertext])]);
const derive = (secret, v, purpose) => Buffer.from(hkdfSync('sha256', secret,
  decoded(v.hkdfSalt), `passkey-vault-kit/v1/${purpose}`, 32));

function encrypt(key, iv, plaintext, aad) {
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  return { iv: encoded(iv), ciphertext: encoded(Buffer.concat([
    cipher.update(plaintext), cipher.final(), cipher.getAuthTag(),
  ])) };
}

function decrypt(key, sealed, aad) {
  const ciphertext = decoded(sealed.ciphertext);
  const decipher = createDecipheriv('aes-256-gcm', key, decoded(sealed.iv));
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
}

export function createReferenceFixture() {
  const prf = bytes(32, 1);
  const recovery = bytes(32, 65);
  const dataKey = bytes(32, 129);
  const plaintext = Buffer.from('Synthetic v1 fixture: \u4e2d\u6587, \u0000 and \ud83d\udd10.');
  const header = {
    version: 1, suite: 'HKDF-SHA-256/A256GCM', id: encoded(bytes(16, 193)),
    hkdfSalt: encoded(bytes(32, 209)),
    binding: { rpId: 'example.com', credentialId: encoded(bytes(8, 33)), prfSalt: encoded(bytes(32, 97)) },
  };
  const passkey = encrypt(derive(prf, header, 'passkey'), bytes(12, 3), dataKey, wrapAad(header, 'passkey'));
  const backup = encrypt(derive(recovery, header, 'recovery'), bytes(12, 51), dataKey, wrapAad(header, 'recovery'));
  const wrapped = { ...header, passkey, recovery: backup };
  return {
    notice: 'PUBLIC SYNTHETIC FIXTURE. All secrets are public; never store real data with them.',
    generator: 'scripts/generate-fixture.mjs using independent node:crypto and FORMAT.md',
    plaintext: encoded(plaintext), prfOutput: encoded(prf), recoveryKey: encoded(recovery),
    vault: { ...wrapped, payload: encrypt(dataKey, bytes(12, 81), plaintext, payloadAad(wrapped)) },
  };
}

export function createReferenceFixtureV2() {
  const prfOutputs = [bytes(32, 1), bytes(32, 141), bytes(32, 173)];
  const recovery = bytes(32, 65);
  // A different data key from the v1 fixture, which uses the same payload IV.
  const dataKey = bytes(32, 157);
  const plaintext = Buffer.from('Synthetic v2 fixture opened by three passkeys and one recovery key.');
  const prfSalt = encoded(bytes(32, 97));
  const bindings = [33, 41, 49].map(start => ({ rpId: 'example.com', credentialId: encoded(bytes(8, start)), prfSalt }));
  const header = { version: 2, suite: 'HKDF-SHA-256/A256GCM', id: encoded(bytes(16, 7)), hkdfSalt: encoded(bytes(32, 23)) };
  const wrap = (index, ivStart) => encrypt(derive(prfOutputs[index], header, 'passkey'), bytes(12, ivStart), dataKey,
    wrapAad(header, 'passkey', bindings[index]));
  const wrapped = {
    ...header, binding: bindings[0], passkey: wrap(0, 5),
    extraPasskeys: [{ binding: bindings[1], passkey: wrap(1, 17) }, { binding: bindings[2], passkey: wrap(2, 29) }],
    recovery: encrypt(derive(recovery, header, 'recovery'), bytes(12, 51), dataKey, wrapAad(header, 'recovery')),
  };
  return {
    notice: 'PUBLIC SYNTHETIC FIXTURE. All secrets are public; never store real data with them.',
    generator: 'scripts/generate-fixture.mjs using independent node:crypto and FORMAT.md',
    plaintext: encoded(plaintext), recoveryKey: encoded(recovery),
    prfOutputs: bindings.map((binding, index) => ({ credentialId: binding.credentialId, prfOutput: encoded(prfOutputs[index]) })),
    vault: { ...wrapped, payload: encrypt(dataKey, bytes(12, 81), plaintext, payloadAad(wrapped)) },
  };
}

/** Open with the recovery secret, or with the PRF output of the passkey slot for credentialId. */
export function openReference(vault, secret, purpose, credentialId = vault.binding.credentialId) {
  const slots = [{ binding: vault.binding, passkey: vault.passkey }, ...(vault.extraPasskeys ?? [])];
  const slot = slots.find(item => item.binding.credentialId === credentialId);
  const sealed = purpose === 'passkey' ? slot.passkey : vault.recovery;
  const rawKey = decrypt(derive(secret, vault, purpose), sealed, wrapAad(vault, purpose, slot.binding));
  return decrypt(rawKey, vault.payload, payloadAad(vault));
}
