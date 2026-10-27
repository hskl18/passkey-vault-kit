import { createPrfBinding, seal, openWithPrf, openWithRecovery, serializeVault, parseVault } from '../dist/index.js';

// This is synthetic key material, not proof of real authenticator compatibility.
const syntheticPrf = crypto.getRandomValues(new Uint8Array(32));
const binding = createPrfBinding('ZGVtby1jcmVkZW50aWFs', 'example.com');
const plaintext = new TextEncoder().encode('A synthetic local note.');
const { vault, recoveryKey } = await seal(plaintext, { binding, prfOutput: syntheticPrf });
const saved = serializeVault(vault);
const reopened = await openWithPrf(parseVault(saved), syntheticPrf);
const recovered = await openWithRecovery(parseVault(saved), recoveryKey);
console.log(JSON.stringify({
  demo: 'synthetic PRF, no authenticator ceremony',
  encryptedEnvelopeChars: saved.length,
  unlockedBytes: reopened.length,
  recoveredBytes: recovered.length,
}, null, 2));
syntheticPrf.fill(0);
plaintext.fill(0);
reopened.fill(0);
recovered.fill(0);
