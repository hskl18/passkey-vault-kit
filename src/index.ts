const SUITE = 'HKDF-SHA-256/A256GCM' as const;
export const MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024;
/** Passkey slots per envelope, including the primary binding. */
export const MAX_PASSKEYS = 8;
export const MAX_SERIALIZED_VAULT_CHARS = Math.ceil((MAX_PLAINTEXT_BYTES + 16) * 4 / 3) + 8192 * MAX_PASSKEYS;
const encoder = new TextEncoder();
// Caller properties can shadow byteLength; enforce limits using the native accessor.
const nativeByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')!.get!;
type OwnedBytes = Uint8Array<ArrayBuffer>;

export type VaultErrorCode = 'INVALID_INPUT' | 'INVALID_ENVELOPE' | 'UNSUPPORTED_VERSION' |
  'UNSUPPORTED_SUITE' | 'CRYPTO_UNAVAILABLE' | 'ENCRYPTION_FAILED' | 'UNLOCK_FAILED' |
  'WEBAUTHN_UNAVAILABLE' | 'WEBAUTHN_FAILED' | 'PRF_UNAVAILABLE' | 'ABORTED';

export class VaultError extends Error {
  constructor(public readonly code: VaultErrorCode) {
    super(code);
    this.name = 'VaultError';
  }
}

export interface PrfBinding {
  /** Persist the RP ID from the credential registration configuration. */
  rpId: string;
  /** Canonical base64url credential ID, not a username. */
  credentialId: string;
  /** Public 32-byte PRF evaluation input, encoded as canonical base64url. */
  prfSalt: string;
}

export interface SealedBytes { iv: string; ciphertext: string }
export interface SealOptions { binding: PrfBinding; prfOutput: Uint8Array }
export interface SealResult { vault: VaultEnvelopeV1; recoveryKey: string }
export interface PrfRequestOptions { signal?: AbortSignal; timeoutMs?: number }
export interface PasskeySlot { binding: PrfBinding; passkey: SealedBytes }
/** Exactly one existing secret that opens the envelope. */
export type PasskeyUnlock = { prfOutput: Uint8Array } | { recoveryKey: string };
interface EnvelopeFields {
  suite: typeof SUITE;
  id: string;
  hkdfSalt: string;
  binding: PrfBinding;
  passkey: SealedBytes;
  recovery: SealedBytes;
  payload: SealedBytes;
}
export interface VaultEnvelopeV1 extends EnvelopeFields { version: 1 }
/** Additional passkeys share the primary binding's RP ID and PRF evaluation input. */
export interface VaultEnvelopeV2 extends EnvelopeFields { version: 2; extraPasskeys: PasskeySlot[] }
export type VaultEnvelope = VaultEnvelopeV1 | VaultEnvelopeV2;
type Unsealed = Omit<VaultEnvelopeV1, 'payload'> | Omit<VaultEnvelopeV2, 'payload'>;

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) throw new VaultError('CRYPTO_UNAVAILABLE');
  return globalThis.crypto;
}

function random(length: number): OwnedBytes {
  return webCrypto().getRandomValues(new Uint8Array(length));
}

function encode(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decode(value: unknown, min: number, max: number, code: VaultErrorCode): OwnedBytes {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) ||
      !/^[A-Za-z0-9_-]+$/.test(value)) throw new VaultError(code);
  let binary: string;
  try { binary = atob(value.replaceAll('-', '+').replaceAll('_', '/')); }
  catch { throw new VaultError(code); }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (bytes.length < min || bytes.length > max || encode(bytes) !== value) {
    // A noncanonical encoding can still decode to a real secret.
    bytes.fill(0);
    throw new VaultError(code);
  }
  return bytes;
}

function record(value: unknown, keys: string[], code: VaultErrorCode, optionalKeys: string[] = []): Record<string, unknown> {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new VaultError(code);
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new VaultError(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string' ||
        (!keys.includes(key) && !optionalKeys.includes(key)))) throw new VaultError(code);
    const entries = [...keys, ...optionalKeys.filter(key => Object.hasOwn(descriptors, key))].map(key => {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw new VaultError(code);
      return [key, descriptor.value as unknown] as const;
    });
    return Object.fromEntries(entries);
  } catch {
    // Direct SDK callers can supply accessors or proxies, unlike parsed JSON.
    throw new VaultError(code);
  }
}

function list(value: unknown, min: number, max: number, code: VaultErrorCode): unknown[] {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new VaultError(code);
    const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(value as object);
    const length: unknown = descriptors['length']?.value;
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < min || length > max ||
        Reflect.ownKeys(descriptors).length !== length + 1) throw new VaultError(code);
    return Array.from({ length }, (_, index) => {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw new VaultError(code);
      return descriptor.value as unknown;
    });
  } catch {
    throw new VaultError(code);
  }
}

function normalizeRpId(value: unknown, code: VaultErrorCode): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253 || /[\s/:@?#%\[\]\\]/u.test(value)) throw new VaultError(code);
  let host: string;
  try { host = new URL(`https://${value}`).hostname; } catch { throw new VaultError(code); }
  if (host.length > 253 || host.endsWith('.') || /^\d+(?:\.\d+)*$/u.test(host) ||
      (host !== 'localhost' && !host.includes('.')) ||
      host.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) throw new VaultError(code);
  return host;
}

function bindingCopy(value: unknown, code: VaultErrorCode): PrfBinding {
  const object = record(value, ['rpId', 'credentialId', 'prfSalt'], code);
  const rpId = normalizeRpId(object.rpId, code);
  decode(object.credentialId, 1, 1024, code);
  decode(object.prfSalt, 32, 32, code);
  return { rpId, credentialId: object.credentialId as string, prfSalt: object.prfSalt as string };
}

function sealedCopy(value: unknown, min: number, max: number): SealedBytes {
  const object = record(value, ['iv', 'ciphertext'], 'INVALID_ENVELOPE');
  decode(object.iv, 12, 12, 'INVALID_ENVELOPE');
  decode(object.ciphertext, min, max, 'INVALID_ENVELOPE');
  return { iv: object.iv as string, ciphertext: object.ciphertext as string };
}

/** Every slot shares one RP ID and PRF input so a single request can offer all credentials. */
function checkSlots(bindings: PrfBinding[], code: VaultErrorCode): void {
  const first = bindings[0];
  if (!first || bindings.some(binding => binding.rpId !== first.rpId || binding.prfSalt !== first.prfSalt) ||
      new Set(bindings.map(binding => binding.credentialId)).size !== bindings.length) throw new VaultError(code);
}

/** Read only the version, so a newer format with unknown fields reports UNSUPPORTED_VERSION. */
function envelopeVersion(value: unknown): unknown {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new VaultError('INVALID_ENVELOPE');
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new VaultError('INVALID_ENVELOPE');
    const descriptor = Object.getOwnPropertyDescriptor(value, 'version');
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw new VaultError('INVALID_ENVELOPE');
    return descriptor.value as unknown;
  } catch {
    throw new VaultError('INVALID_ENVELOPE');
  }
}

/** Validate and copy untrusted JSON before any asynchronous operation. */
export function validateVault(value: unknown): VaultEnvelope {
  const version = envelopeVersion(value);
  if (!Number.isSafeInteger(version)) throw new VaultError('INVALID_ENVELOPE');
  if (version !== 1 && version !== 2) throw new VaultError('UNSUPPORTED_VERSION');
  const fields = ['version', 'suite', 'id', 'hkdfSalt', 'binding', 'passkey', 'recovery', 'payload'];
  const object = version === 2
    ? record(value, [...fields, 'extraPasskeys'], 'INVALID_ENVELOPE')
    : record(value, fields, 'INVALID_ENVELOPE');
  if (object.version !== version || typeof object.suite !== 'string') throw new VaultError('INVALID_ENVELOPE');
  if (object.suite !== SUITE) throw new VaultError('UNSUPPORTED_SUITE');
  decode(object.id, 16, 16, 'INVALID_ENVELOPE');
  decode(object.hkdfSalt, 32, 32, 'INVALID_ENVELOPE');
  const header = { suite: SUITE, id: object.id as string, hkdfSalt: object.hkdfSalt as string,
    binding: bindingCopy(object.binding, 'INVALID_ENVELOPE'), passkey: sealedCopy(object.passkey, 48, 48) };
  const rest = { recovery: sealedCopy(object.recovery, 48, 48), payload: sealedCopy(object.payload, 16, MAX_PLAINTEXT_BYTES + 16) };
  if (object.version === 1) return { version: 1, ...header, ...rest };
  const extraPasskeys = list(object.extraPasskeys, 1, MAX_PASSKEYS - 1, 'INVALID_ENVELOPE').map(slot => {
    const slotFields = record(slot, ['binding', 'passkey'], 'INVALID_ENVELOPE');
    return { binding: bindingCopy(slotFields.binding, 'INVALID_ENVELOPE'), passkey: sealedCopy(slotFields.passkey, 48, 48) };
  });
  checkSlots([header.binding, ...extraPasskeys.map(slot => slot.binding)], 'INVALID_ENVELOPE');
  return { version: 2, ...header, extraPasskeys, ...rest };
}

/** Bindings for every passkey that can open the envelope, primary first. */
export function vaultBindings(value: VaultEnvelope): PrfBinding[] {
  const vault = validateVault(value);
  return [vault.binding, ...(vault.version === 2 ? vault.extraPasskeys.map(slot => slot.binding) : [])];
}

export function parseVault(json: string): VaultEnvelope {
  if (typeof json !== 'string' || json.length > MAX_SERIALIZED_VAULT_CHARS) throw new VaultError('INVALID_ENVELOPE');
  let value: unknown;
  try { value = JSON.parse(json); } catch { throw new VaultError('INVALID_ENVELOPE'); }
  return validateVault(value);
}

export function serializeVault(vault: VaultEnvelope): string {
  return JSON.stringify(validateVault(vault));
}

/** Preserve this binding alongside the encrypted envelope for later PRF evaluation. */
export function createPrfBinding(credentialId: string, rpId: string): PrfBinding {
  decode(credentialId, 1, 1024, 'INVALID_INPUT');
  return { rpId: normalizeRpId(rpId, 'INVALID_INPUT'), credentialId, prfSalt: encode(random(32)) };
}

function secretCopy(value: unknown): OwnedBytes {
  try {
    if (!(value instanceof Uint8Array) || nativeByteLength.call(value) !== 32) throw new VaultError('INVALID_INPUT');
    const copy = new Uint8Array(value);
    if (copy.byteLength !== 32) throw new VaultError('INVALID_INPUT');
    return copy;
  } catch { throw new VaultError('INVALID_INPUT'); }
}

// Wrapped keys keep format 1 data so upgrading an envelope to v2 preserves every existing slot.
function aad(vault: Pick<VaultEnvelope, 'suite' | 'id' | 'hkdfSalt'>,
  purpose: 'recovery' | 'passkey', binding?: PrfBinding): OwnedBytes {
  const fields = ['passkey-vault-kit', 1, vault.suite, vault.id, vault.hkdfSalt, purpose];
  if (binding) fields.push(binding.rpId, binding.credentialId, binding.prfSalt);
  return encoder.encode(JSON.stringify(fields));
}

/** The payload authenticates the whole public header, including every wrapped key. */
function payloadAad(vault: Unsealed): OwnedBytes {
  const fields: (string | number)[] = ['passkey-vault-kit', vault.version, vault.suite, vault.id,
    vault.hkdfSalt, 'payload', vault.binding.rpId, vault.binding.credentialId, vault.binding.prfSalt,
    vault.passkey.iv, vault.passkey.ciphertext, vault.recovery.iv, vault.recovery.ciphertext];
  if (vault.version === 2) {
    for (const { binding, passkey } of vault.extraPasskeys) {
      fields.push(binding.rpId, binding.credentialId, binding.prfSalt, passkey.iv, passkey.ciphertext);
    }
  }
  return encoder.encode(JSON.stringify(fields));
}

async function derive(secret: OwnedBytes, salt: string, purpose: 'passkey' | 'recovery'): Promise<CryptoKey> {
  const subtle = webCrypto().subtle;
  const material = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256',
    salt: decode(salt, 32, 32, 'INVALID_ENVELOPE'),
    info: encoder.encode(`passkey-vault-kit/v1/${purpose}`),
  }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function dataKey(raw: OwnedBytes): Promise<CryptoKey> {
  return webCrypto().subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encrypt(key: CryptoKey, plaintext: OwnedBytes, additionalData: OwnedBytes): Promise<SealedBytes> {
  const iv = random(12);
  const ciphertext = await webCrypto().subtle.encrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 }, key, plaintext);
  return { iv: encode(iv), ciphertext: encode(new Uint8Array(ciphertext)) };
}

async function decrypt(key: CryptoKey, sealed: SealedBytes, additionalData: OwnedBytes): Promise<OwnedBytes> {
  const plaintext = await webCrypto().subtle.decrypt({ name: 'AES-GCM',
    iv: decode(sealed.iv, 12, 12, 'INVALID_ENVELOPE'), additionalData, tagLength: 128,
  }, key, decode(sealed.ciphertext, 16, MAX_PLAINTEXT_BYTES + 16, 'INVALID_ENVELOPE'));
  return new Uint8Array(plaintext);
}

/** Encrypt once, with independent passkey and recovery wrapping keys. No storage or network writes. */
export async function seal(plaintext: Uint8Array, options: SealOptions): Promise<SealResult> {
  let binding: PrfBinding;
  let prf: OwnedBytes;
  try {
    if (!(plaintext instanceof Uint8Array) || nativeByteLength.call(plaintext) > MAX_PLAINTEXT_BYTES) throw new VaultError('INVALID_INPUT');
    const supplied = record(options, ['binding', 'prfOutput'], 'INVALID_INPUT');
    binding = bindingCopy(supplied.binding, 'INVALID_INPUT');
    prf = secretCopy(supplied.prfOutput);
  } catch { throw new VaultError('INVALID_INPUT'); }
  let rawKey: OwnedBytes | undefined;
  let recovery: OwnedBytes | undefined;
  let input: OwnedBytes | undefined;
  try {
    input = new Uint8Array(plaintext);
    if (input.byteLength > MAX_PLAINTEXT_BYTES) throw new VaultError('INVALID_INPUT');
    rawKey = random(32);
    recovery = random(32);
    const header = { version: 1 as const, suite: SUITE, id: encode(random(16)), hkdfSalt: encode(random(32)) };
    const key = await dataKey(rawKey);
    const passkey = await encrypt(await derive(prf, header.hkdfSalt, 'passkey'), rawKey, aad(header, 'passkey', binding));
    const backup = await encrypt(await derive(recovery, header.hkdfSalt, 'recovery'), rawKey, aad(header, 'recovery'));
    const wrapped: Omit<VaultEnvelopeV1, 'payload'> = { ...header, binding, passkey, recovery: backup };
    const payload = await encrypt(key, input, payloadAad(wrapped));
    return { vault: { ...wrapped, payload }, recoveryKey: encode(recovery) };
  } catch (error) {
    if (error instanceof VaultError) throw error;
    throw new VaultError('ENCRYPTION_FAILED');
  } finally {
    prf.fill(0); rawKey?.fill(0); recovery?.fill(0); input?.fill(0);
  }
}

async function unwrapKey(vault: VaultEnvelope, secret: OwnedBytes, purpose: 'passkey' | 'recovery'): Promise<OwnedBytes> {
  const key = await derive(secret, vault.hkdfSalt, purpose);
  if (purpose === 'recovery') return decrypt(key, vault.recovery, aad(vault, 'recovery'));
  const slots = [{ binding: vault.binding, passkey: vault.passkey }, ...(vault.version === 2 ? vault.extraPasskeys : [])];
  for (const slot of slots) {
    try { return await decrypt(key, slot.passkey, aad(vault, 'passkey', slot.binding)); }
    catch { /* A PRF output opens only the slot of the credential that produced it. */ }
  }
  throw new VaultError('UNLOCK_FAILED');
}

async function unlock(value: VaultEnvelope, secret: OwnedBytes, purpose: 'passkey' | 'recovery'): Promise<OwnedBytes> {
  let rawKey: OwnedBytes | undefined;
  try {
    const vault = validateVault(value);
    rawKey = await unwrapKey(vault, secret, purpose);
    if (rawKey.byteLength !== 32) throw new VaultError('UNLOCK_FAILED');
    return await decrypt(await dataKey(rawKey), vault.payload, payloadAad(vault));
  } catch (error) {
    if (error instanceof VaultError) throw error;
    throw new VaultError('UNLOCK_FAILED');
  } finally { secret.fill(0); rawKey?.fill(0); }
}

/** Try each passkey slot; the output only opens the slot of the credential that produced it. */
export async function openWithPrf(vault: VaultEnvelope, prfOutput: Uint8Array): Promise<OwnedBytes> {
  return unlock(vault, secretCopy(prfOutput), 'passkey');
}

export async function openWithRecovery(vault: VaultEnvelope, recoveryKey: string): Promise<OwnedBytes> {
  return unlock(vault, decode(recoveryKey, 32, 32, 'INVALID_INPUT'), 'recovery');
}

/**
 * Wrap the existing data key for another credential and return a v2 envelope.
 * The new binding must reuse the envelope's RP ID and PRF input; the recovery key is unchanged.
 * Removing a slot later is not revocation: reseal with a new data key to revoke a credential.
 */
export async function addPasskey(value: VaultEnvelope, unlockWith: PasskeyUnlock, addition: SealOptions): Promise<VaultEnvelopeV2> {
  const vault = validateVault(value);
  const bindings = [vault.binding, ...(vault.version === 2 ? vault.extraPasskeys.map(slot => slot.binding) : [])];
  let secret: OwnedBytes | undefined;
  let prf: OwnedBytes | undefined;
  let binding: PrfBinding;
  let purpose: 'passkey' | 'recovery';
  try {
    const unlockFields = record(unlockWith, [], 'INVALID_INPUT', ['prfOutput', 'recoveryKey']);
    const [method, ...others] = Object.keys(unlockFields);
    if (method === undefined || others.length > 0) throw new VaultError('INVALID_INPUT');
    purpose = method === 'prfOutput' ? 'passkey' : 'recovery';
    secret = purpose === 'passkey' ? secretCopy(unlockFields.prfOutput) : decode(unlockFields.recoveryKey, 32, 32, 'INVALID_INPUT');
    const supplied = record(addition, ['binding', 'prfOutput'], 'INVALID_INPUT');
    binding = bindingCopy(supplied.binding, 'INVALID_INPUT');
    prf = secretCopy(supplied.prfOutput);
    if (bindings.length >= MAX_PASSKEYS) throw new VaultError('INVALID_INPUT');
    checkSlots([...bindings, binding], 'INVALID_INPUT');
  } catch {
    secret?.fill(0); prf?.fill(0);
    throw new VaultError('INVALID_INPUT');
  }
  let rawKey: OwnedBytes | undefined;
  let plaintext: OwnedBytes | undefined;
  try {
    rawKey = await unwrapKey(vault, secret, purpose);
    if (rawKey.byteLength !== 32) throw new VaultError('UNLOCK_FAILED');
    const key = await dataKey(rawKey);
    plaintext = await decrypt(key, vault.payload, payloadAad(vault));
    // An output that already opens a slot came from an enrolled credential, not the new one.
    const enrolled = await unwrapKey(vault, prf, 'passkey').then(bytes => { bytes.fill(0); return true; }, () => false);
    if (enrolled) throw new VaultError('INVALID_INPUT');
    try {
      const slot = { binding, passkey: await encrypt(await derive(prf, vault.hkdfSalt, 'passkey'), rawKey, aad(vault, 'passkey', binding)) };
      const next: Omit<VaultEnvelopeV2, 'payload'> = {
        version: 2, suite: vault.suite, id: vault.id, hkdfSalt: vault.hkdfSalt, binding: vault.binding, passkey: vault.passkey,
        extraPasskeys: [...(vault.version === 2 ? vault.extraPasskeys : []), slot], recovery: vault.recovery,
      };
      return { ...next, payload: await encrypt(key, plaintext, payloadAad(next)) };
    } catch {
      throw new VaultError('ENCRYPTION_FAILED');
    }
  } catch (error) {
    if (error instanceof VaultError) throw error;
    throw new VaultError('UNLOCK_FAILED');
  } finally { secret.fill(0); prf.fill(0); rawKey?.fill(0); plaintext?.fill(0); }
}

function signalAborted(signal: AbortSignal | undefined): boolean {
  if (signal === undefined) return false;
  if (typeof AbortSignal === 'undefined') throw new VaultError('INVALID_INPUT');
  const getter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
  if (!getter) throw new VaultError('INVALID_INPUT');
  // The native getter validates the brand without exposing a caller-supplied abort reason.
  try { return getter.call(signal) as boolean; }
  catch { throw new VaultError('INVALID_INPUT'); }
}

/**
 * Request the PRF output with a fresh challenge and required user verification.
 * Pass `vaultBindings(vault)` to let the user choose any credential that can open the envelope.
 */
export async function requestPrf(value: PrfBinding | readonly PrfBinding[], options: PrfRequestOptions = {}): Promise<OwnedBytes> {
  let bindings: PrfBinding[];
  try {
    // Array.isArray throws for a revoked proxy.
    bindings = Array.isArray(value)
      ? list(value, 1, MAX_PASSKEYS, 'INVALID_INPUT').map(item => bindingCopy(item, 'INVALID_INPUT'))
      : [bindingCopy(value, 'INVALID_INPUT')];
  } catch {
    throw new VaultError('INVALID_INPUT');
  }
  checkSlots(bindings, 'INVALID_INPUT');
  const binding = bindings[0];
  if (!binding) throw new VaultError('INVALID_INPUT');
  const supplied = record(options, [], 'INVALID_INPUT', ['timeoutMs', 'signal']);
  const timeout = supplied.timeoutMs === undefined ? 60_000 : supplied.timeoutMs;
  const signal = supplied.signal as AbortSignal | undefined;
  if (typeof timeout !== 'number' || !Number.isSafeInteger(timeout) || timeout < 1000 || timeout > 120_000) throw new VaultError('INVALID_INPUT');
  if (signalAborted(signal)) throw new VaultError('ABORTED');
  if (typeof navigator === 'undefined' || typeof PublicKeyCredential === 'undefined' ||
      !navigator.credentials || !globalThis.isSecureContext) throw new VaultError('WEBAUTHN_UNAVAILABLE');
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: random(32), timeout, rpId: binding.rpId, userVerification: 'required',
    allowCredentials: bindings.map(item => ({ type: 'public-key' as const, id: decode(item.credentialId, 1, 1024, 'INVALID_INPUT') })),
    extensions: { prf: { eval: { first: decode(binding.prfSalt, 32, 32, 'INVALID_INPUT') } } },
  };
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({ publicKey, ...(signal ? { signal } : {}) });
  } catch {
    throw new VaultError(signalAborted(signal) ? 'ABORTED' : 'WEBAUTHN_FAILED');
  }
  if (signalAborted(signal)) throw new VaultError('ABORTED');
  if (!(credential instanceof PublicKeyCredential) ||
      !bindings.some(item => item.credentialId === encode(new Uint8Array(credential.rawId)))) throw new VaultError('WEBAUTHN_FAILED');
  const result = credential.getClientExtensionResults().prf?.results?.first;
  if (!result || result.byteLength !== 32) throw new VaultError('PRF_UNAVAILABLE');
  const output = ArrayBuffer.isView(result)
    ? new Uint8Array(new Uint8Array(result.buffer, result.byteOffset, result.byteLength))
    : new Uint8Array(result.slice(0));
  if (output.byteLength !== 32) throw new VaultError('PRF_UNAVAILABLE');
  return output;
}
