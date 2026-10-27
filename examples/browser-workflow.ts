import { addPasskey, createPrfBinding, openWithPrf, parseVault, requestPrf, seal, serializeVault, vaultBindings } from 'passkey-vault-kit';

/** After verified registration requesting extensions.prf = {}, check prf.enabled, then call from a user gesture. */
export async function encryptNote(credentialId: string, registrationRpId: string, text: string):
  Promise<{ encryptedJson: string; recoveryKey: string }> {
  const binding = createPrfBinding(credentialId, registrationRpId);
  const secret = await requestPrf(binding);
  const plaintext = new TextEncoder().encode(text);
  try {
    const { vault, recoveryKey } = await seal(plaintext, { binding, prfOutput: secret });
    return { encryptedJson: serializeVault(vault), recoveryKey };
  } finally {
    secret.fill(0);
    plaintext.fill(0);
  }
}

/** The caller owns persistence, display, recovery-key storage, and the returned plaintext. */
export async function decryptNote(encryptedJson: string, signal?: AbortSignal): Promise<Uint8Array> {
  const vault = parseVault(encryptedJson);
  const secret = await requestPrf(vaultBindings(vault), signal ? { signal } : {});
  try {
    return await openWithPrf(vault, secret);
  } finally {
    secret.fill(0);
  }
}

/** After verified registration of another PRF-capable credential, let it open the same envelope too. */
export async function addDevice(encryptedJson: string, newCredentialId: string): Promise<string> {
  const vault = parseVault(encryptedJson);
  const binding = { ...vault.binding, credentialId: newCredentialId };
  let added: Uint8Array | undefined;
  let existing: Uint8Array | undefined;
  try {
    // Ask the new device first, so one without PRF support fails before an enrolled secret is read.
    added = await requestPrf(binding);
    existing = await requestPrf(vaultBindings(vault));
    return serializeVault(await addPasskey(vault, { prfOutput: existing }, { binding, prfOutput: added }));
  } finally {
    added?.fill(0);
    existing?.fill(0);
  }
}
