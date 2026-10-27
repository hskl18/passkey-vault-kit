# Passkey Vault Kit

A small TypeScript library that encrypts local data and unlocks it with a passkey's WebAuthn PRF output or an independent recovery key.
It uses the platform WebCrypto API and has no runtime dependencies, account service, telemetry, or storage integration.
It has not received an independent cryptographic audit; see [SECURITY.md](SECURITY.md) for the trust boundary.

## What it does

- Encrypts up to 16 MiB with a random AES-256-GCM data key.
- Wraps that key separately for each passkey (up to eight) and for a random recovery secret.
- Validates a bounded, versioned JSON envelope before any cryptography ([FORMAT.md](FORMAT.md)).
- Requests PRF output in a secure browser context, offering every passkey that can open an envelope in one prompt.

Registration and server-side authentication stay with your WebAuthn library.
Never substitute a credential ID, signature, or session token for PRF output, and never send PRF output to a server.

## Develop

```sh
npm ci
npm run check   # strict build, behavioral tests, and an offline install of the real npm archive
npm run demo    # Node demonstration with synthetic PRF material
```

Node.js 22.13 or newer is required.
The package is not yet published to npm; build a local archive with `npm pack`.
The optional real-browser regression is described in [test/browser/README.md](test/browser/README.md).
[integration/verified-notes](integration/verified-notes/README.md) is a runnable notes app: SimpleWebAuthn verifies registration and login on a local server, while PRF evaluation, encryption, and recovery stay in the browser.

## Use

Request the PRF extension at registration and continue only when the credential reports it:

```ts
const credential = await navigator.credentials.create({
  publicKey: { ...registrationOptions, extensions: { ...registrationOptions.extensions, prf: {} } },
});
if (!(credential instanceof PublicKeyCredential)) throw new Error('No public-key credential');
// Verify the registration on your server first.
if (credential.getClientExtensionResults().prf?.enabled !== true) throw new Error('No PRF support');
```

Seal, store, and unlock:

```ts
import { createPrfBinding, requestPrf, seal, openWithPrf, openWithRecovery,
  serializeVault, parseVault, vaultBindings, addPasskey } from 'passkey-vault-kit';

const binding = createPrfBinding(credential.id, 'example.com'); // the registration RP ID
const prfOutput = await requestPrf(binding);
let stored: string;
try {
  const { vault, recoveryKey } = await seal(new TextEncoder().encode('A local note'), { binding, prfOutput });
  stored = serializeVault(vault); // persist; show recoveryKey once and have the user save it
} finally {
  prfOutput.fill(0);
}

const saved = parseVault(stored);
const unlockOutput = await requestPrf(vaultBindings(saved)); // any passkey on the envelope
try {
  const bytes = await openWithPrf(saved, unlockOutput);
} finally {
  unlockOutput.fill(0);
}
const recovered = await openWithRecovery(saved, userProvidedRecoveryKey);
```

Add another passkey, for example a second device, without changing the recovery key:

```ts
const extra = { ...saved.binding, credentialId: newCredential.id }; // same RP ID and PRF input
let added: Uint8Array | undefined;
let existing: Uint8Array | undefined;
try {
  added = await requestPrf(extra); // the new device first
  existing = await requestPrf(vaultBindings(saved));
  const withBoth = await addPasskey(saved, { prfOutput: existing }, { binding: extra, prfOutput: added }); // or { recoveryKey }
} finally {
  added?.fill(0);
  existing?.fill(0);
}
```

Clear PRF outputs and plaintext buffers with `fill(0)` when you are done with them, as above.
`requestPrf` requires user verification and fails rather than falling back to a password or plaintext.
Support depends on the browser, authenticator, credential provider, and credential; a successful 32-byte `requestPrf` result is the only reliable check.

## Recovery and rotation

Losing every usable passkey and the recovery key makes the data unrecoverable, so verify recovery before relying on it.
Resealing creates a new data key and recovery key; use it to move to a new RP ID or to revoke a passkey.
Removing a passkey's slot is not revocation, because that credential could already unwrap the data key.

Replace an envelope in this order:

1. Keep the current envelope and its recovery key until the replacement is checked.
2. Recover the plaintext, `seal` it with the new binding, and add any other passkeys.
3. Write the candidate to a separate record, read it back, and open the stored copy with every passkey and the new recovery key.
4. Have the user save the new recovery key, then switch the current-envelope reference in one storage transaction.

The library performs no persistence; storage durability, eviction, and backups belong to the application.
Older envelopes that someone retained stay decryptable with their old secrets.

## API

| Function | Result |
| --- | --- |
| `createPrfBinding(credentialId, rpId)` | RP ID, credential ID, and a random public PRF input to persist |
| `requestPrf(binding \| bindings, options?)` | 32-byte PRF output from one of the listed credentials |
| `seal(bytes, { binding, prfOutput })` | A v1 envelope and a separate recovery key |
| `addPasskey(vault, { prfOutput } \| { recoveryKey }, { binding, prfOutput })` | A v2 envelope that the new passkey can also open |
| `openWithPrf(vault, prfOutput)` | The decrypted bytes, trying each passkey slot |
| `openWithRecovery(vault, recoveryKey)` | The decrypted bytes |
| `vaultBindings(vault)` | Bindings of every passkey on the envelope, primary first |
| `parseVault(json)`, `serializeVault(vault)` | Validated envelope, canonical JSON |
| `validateVault(value)` | A validated copy of an already parsed envelope object |

`MAX_PLAINTEXT_BYTES` (16 MiB), `MAX_PASSKEYS` (8), and `MAX_SERIALIZED_VAULT_CHARS` are exported limits.

Failures throw `VaultError` with a `code` and never include secrets or plaintext.

| Code | Meaning |
| --- | --- |
| `INVALID_INPUT` | A secret, binding, option, or plaintext breaks the API contract, including an added passkey that duplicates a slot, uses a different RP ID or PRF input, or whose output already opens the envelope |
| `INVALID_ENVELOPE` | Envelope structure, bounds, or encoding is invalid |
| `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE` | The envelope version or suite is not supported |
| `CRYPTO_UNAVAILABLE`, `ENCRYPTION_FAILED` | Native WebCrypto is missing or failed |
| `UNLOCK_FAILED` | The secret is wrong or authenticated data was changed |
| `WEBAUTHN_UNAVAILABLE`, `WEBAUTHN_FAILED` | No usable secure WebAuthn API, or the request failed or was dismissed |
| `PRF_UNAVAILABLE` | The credential did not return a 32-byte PRF output |
| `ABORTED` | The supplied `AbortSignal` cancelled the request |

Records must contain only their documented own data properties; getters, symbols, and unknown fields are rejected.
Completed checks and open release gates are in [VERIFICATION.md](VERIFICATION.md) and [RELEASING.md](RELEASING.md).

## References

- [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) and the [W3C PRF explainer](https://github.com/w3c/webauthn/blob/main/explainers/prf-extension.md)
- [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
- [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869)

MIT licensed.
