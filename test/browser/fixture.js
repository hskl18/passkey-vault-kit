import { createPrfBinding, openWithPrf, openWithRecovery, parseVault, requestPrf, seal, serializeVault } from '/sdk.js';

const message = 'Synthetic anonymous browser note: \u4e2d\u6587 \ud83d\udd10.';
const storageKey = 'synthetic-prf-envelope';
const pendingKey = `${storageKey}:pending`;
const bytes = () => new Uint8Array([239, 187, 191, 0, 255, ...new TextEncoder().encode(message)]);
let previousPrf;
function check(condition, label) { if (!condition) throw new Error(label); }
const getPrf = binding => requestPrf(binding, { signal: AbortSignal.timeout(10000) });
function checkPlaintext(plaintext) {
  try {
    const expected = bytes();
    check(plaintext.byteLength === expected.byteLength && plaintext.every((byte, index) => byte === expected[index]),
      'application bytes changed');
  } finally { plaintext.fill(0); }
}
function checkUnchanged(original, pending) {
  check(localStorage.getItem(storageKey) === original && localStorage.getItem(pendingKey) === pending,
    'failed operation changed persisted envelopes');
}

async function register() {
  const credential = await navigator.credentials.create({ signal: AbortSignal.timeout(10000), publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { id: 'localhost', name: 'Synthetic local test' },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'synthetic-user', displayName: 'Synthetic user' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: 10000,
    extensions: { prf: {} },
  } });
  check(credential instanceof PublicKeyCredential, 'registration returned no credential');
  return credential;
}

window.trial = {
  async create() {
    const credential = await register();
    check(credential.getClientExtensionResults().prf?.enabled === true, 'PRF not enabled at registration');
    const binding = createPrfBinding(credential.id, 'localhost');
    const secret = await getPrf(binding);
    try {
      const { vault, recoveryKey } = await seal(bytes(), { binding, prfOutput: secret });
      checkPlaintext(await openWithPrf(vault, secret));
      checkPlaintext(await openWithRecovery(vault, recoveryKey));
      localStorage.setItem(storageKey, serializeVault(vault));
      return { recoveryKey, prfBytes: secret.byteLength, plaintextBytes: bytes().byteLength };
    } finally { secret.fill(0); }
  },

  async reopen() {
    const vault = parseVault(localStorage.getItem(storageKey));
    const secret = await getPrf(vault.binding);
    try {
      checkPlaintext(await openWithPrf(vault, secret));
      return { rpId: vault.binding.rpId, prfBytes: secret.byteLength, envelopeId: vault.id };
    } finally { secret.fill(0); }
  },

  async rememberPrfForRejection() {
    previousPrf?.fill(0);
    previousPrf = await getPrf(parseVault(localStorage.getItem(storageKey)).binding);
    return { bytes: previousPrf.byteLength };
  },

  async recoverAndRotate(recoveryKey) {
    const original = localStorage.getItem(storageKey);
    const oldVault = parseVault(original);
    let plaintext;
    let secret;
    try {
      plaintext = await openWithRecovery(oldVault, recoveryKey);
      const credential = await register();
      check(credential.getClientExtensionResults().prf?.enabled === true, 'replacement PRF unavailable');
      const binding = createPrfBinding(credential.id, 'localhost');
      check(binding.credentialId !== oldVault.binding.credentialId, 'replacement reused original credential');
      secret = await getPrf(binding);
      const result = await seal(plaintext, { binding, prfOutput: secret });
      check(result.recoveryKey !== recoveryKey && result.vault.id !== oldVault.id, 'replacement reused old state');
      let oldSecretRejected = false;
      try { await openWithRecovery(result.vault, recoveryKey); }
      catch (error) { oldSecretRejected = error.code === 'UNLOCK_FAILED'; }
      check(oldSecretRejected, 'old recovery secret unlocked new envelope');
      check(previousPrf?.byteLength === 32, 'missing rejection-only old PRF');
      let oldPrfRejected = false;
      try { await openWithPrf(result.vault, previousPrf); }
      catch (error) { oldPrfRejected = error.code === 'UNLOCK_FAILED'; }
      check(oldPrfRejected, 'old PRF unlocked replacement');
      checkPlaintext(await openWithPrf(result.vault, secret));
      checkPlaintext(await openWithRecovery(result.vault, result.recoveryKey));
      localStorage.setItem(pendingKey, serializeVault(result.vault));
      const stored = parseVault(localStorage.getItem(pendingKey));
      checkPlaintext(await openWithRecovery(stored, result.recoveryKey));
      check(localStorage.getItem(storageKey) === original, 'preparation replaced original envelope');
      return { recoveryKey: result.recoveryKey, changedBinding: true, oldSecretRejected, oldPrfRejected,
        originalPreserved: true, pendingReadBack: true };
    } finally {
      secret?.fill(0); plaintext?.fill(0); previousPrf?.fill(0); previousPrf = undefined;
    }
  },

  async rejectPending(recoveryKey) {
    const original = localStorage.getItem(storageKey);
    const pending = localStorage.getItem(pendingKey);
    let rejected = false;
    try { await openWithRecovery(parseVault(pending), recoveryKey); }
    catch (error) { rejected = error.code === 'UNLOCK_FAILED'; }
    check(rejected, 'wrong recovery key unlocked pending envelope');
    checkUnchanged(original, pending);
    checkPlaintext(await openWithRecovery(parseVault(original), recoveryKey));
    return { rejected, originalPreserved: true, oldSnapshotStillRecoverable: true };
  },

  async commitRotation(recoveryKey) {
    const pending = localStorage.getItem(pendingKey);
    const candidate = parseVault(pending);
    checkPlaintext(await openWithRecovery(candidate, recoveryKey));
    const secret = await getPrf(candidate.binding);
    try {
      checkPlaintext(await openWithPrf(candidate, secret));
      localStorage.setItem(storageKey, pending);
      checkPlaintext(await openWithRecovery(parseVault(localStorage.getItem(storageKey)), recoveryKey));
      localStorage.removeItem(pendingKey);
      return { newRecoveryVerified: true, storedPrfVerified: true, envelopeId: candidate.id };
    } finally { secret.fill(0); }
  },

  async recoveryOnly(recoveryKey) {
    checkPlaintext(await openWithRecovery(parseVault(localStorage.getItem(storageKey)), recoveryKey));
    return { recoveryVerified: true };
  },

  async cancel() {
    const original = localStorage.getItem(storageKey);
    const pending = localStorage.getItem(pendingKey);
    const vault = parseVault(localStorage.getItem(storageKey));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 100);
    try {
      await requestPrf(vault.binding, { signal: controller.signal });
      throw new Error('cancelled request returned a secret');
    } catch (error) {
      check(error.code === 'ABORTED', 'cancellation error contract changed');
      checkUnchanged(original, pending);
      return { code: error.code, originalPreserved: true };
    } finally { clearTimeout(timer); }
  },

  async unsupported(recoveryKey) {
    const original = localStorage.getItem(storageKey);
    const pending = localStorage.getItem(pendingKey);
    const credential = await register();
    check(credential.getClientExtensionResults().prf?.enabled !== true, 'unsupported fixture enabled PRF');
    const binding = createPrfBinding(credential.id, 'localhost');
    try {
      await getPrf(binding);
      throw new Error('unsupported credential returned a secret');
    } catch (error) {
      check(error.code === 'PRF_UNAVAILABLE', 'unsupported credential error contract changed');
      checkUnchanged(original, pending);
      checkPlaintext(await openWithRecovery(parseVault(original), recoveryKey));
      return { code: error.code, originalPreserved: true, recoveryVerified: true };
    }
  },
};
document.getElementById('status').textContent = 'Fixture ready; virtual-authenticator runner required.';
