# Envelope format

## Version 1

All binary fields use canonical unpadded base64url.
The suite identifier is exactly `HKDF-SHA-256/A256GCM`.
Unknown versions, suites, or fields are rejected.
The RP ID is normalized to an ASCII lowercase hostname before it is included in authenticated data.

| Field | Meaning |
| --- | --- |
| `version` | Integer `1` |
| `suite` | `HKDF-SHA-256/A256GCM` |
| `id` | Random 16-byte envelope identifier |
| `hkdfSalt` | Random 32-byte HKDF salt |
| `binding.rpId` | Canonical ASCII RP hostname from registration, without scheme, port, or path |
| `binding.credentialId` | Credential ID between 1 and 1024 bytes |
| `binding.prfSalt` | Public 32-byte WebAuthn PRF evaluation input |
| `passkey` | Data key encrypted using the PRF-derived wrapping key |
| `recovery` | Data key encrypted using the recovery-derived wrapping key |
| `payload` | Application bytes encrypted using the random data key |

Every encrypted field contains a random 12-byte `iv` and a `ciphertext` containing the 128-bit GCM tag.
The data key, PRF output, and recovery secret are each 32 bytes.
The two wrapping ciphertexts are therefore each 48 bytes.
The plaintext ceiling is 16 MiB, and all processing is buffered in memory.

Wrapping keys are nonextractable AES-256-GCM keys derived with HKDF-SHA-256.
The HKDF salt is `hkdfSalt` and the UTF-8 info string is either `passkey-vault-kit/v1/passkey` or `passkey-vault-kit/v1/recovery`.
The input key material is respectively the PRF output or the raw recovery secret.

The additional authenticated data is the UTF-8 encoding of `JSON.stringify` applied to the ordered array below.

```text
["passkey-vault-kit", 1, suite, id, hkdfSalt, purpose]
```

The purpose is `recovery` or `passkey` for a wrapped key.
For `passkey` only, append `binding.rpId`, `binding.credentialId`, and `binding.prfSalt` to that array.
This binds each encrypted component to its envelope, role, and, for the passkey slot, the evaluation binding.
For the payload, use the same base array with purpose `payload` and append `binding.rpId`, `binding.credentialId`, `binding.prfSalt`, `passkey.iv`, `passkey.ciphertext`, `recovery.iv`, and `recovery.ciphertext`, in that order.
This authenticates the entire public header and both wrapped keys when decrypting the payload.
Opening with one method still does not prove that the caller possesses the other secret or that another authenticator remains available.
Applications must exercise recovery separately.

The outer metadata is visible to anyone holding the envelope.
This format is an application-specific envelope and is not JWE, age, or a standardized password-manager export format.

## Version 2

Version 2 lets several passkeys open the same envelope.
`addPasskey` produces it from a v1 or v2 envelope; `seal` still produces v1.
The upgrade is one-way: readers that support only version 1 reject v2 envelopes, and returning to v1 requires recovering the plaintext and calling `seal`.
It contains every v1 field with `version` set to `2`, plus `extraPasskeys` between `passkey` and `recovery`.

| Field | Meaning |
| --- | --- |
| `extraPasskeys` | Array of 1 to 7 slots, each `{ binding, passkey }` |
| `extraPasskeys[].binding` | Same RP ID and `prfSalt` as the primary `binding`, with a different credential ID |
| `extraPasskeys[].passkey` | The same data key encrypted using that credential's PRF-derived wrapping key |

All slots share one RP ID, because a WebAuthn request has a single RP ID.
They also share one PRF evaluation input, so a single `prf.eval` input serves every listed credential without relying on `evalByCredential` support.
PRF outputs still differ per credential because each credential has its own PRF secret.
Credential IDs must be unique across the primary binding and every extra slot.

Each extra slot uses the same HKDF derivation and wrapped-key AAD as the v1 `passkey` slot, with its own binding appended.
The version element of every wrapped-key AAD stays `1`, so adding a slot never re-encrypts existing slots or the recovery key.
The payload AAD uses version `2` and appends `rpId`, `credentialId`, `prfSalt`, `passkey.iv`, and `passkey.ciphertext` for each extra slot, in array order, after the v1 payload fields.
Adding a slot therefore re-encrypts the payload under the existing data key with a fresh IV.
Without the data key, removing, reordering, or replacing any slot makes the payload fail authentication.
Anyone who can open the envelope, through any passkey or the recovery key, holds the data key and can produce a different valid envelope.

Adding a passkey does not rotate the data key or the recovery key.
A credential that has ever been able to open an envelope keeps the data key it unwrapped, so dropping its slot is not revocation.
To revoke a credential, recover the plaintext and `seal` a new envelope, then add the remaining passkeys to it.

## Public synthetic fixtures

[examples/v1-fixture.json](examples/v1-fixture.json) contains a fixed v1 envelope and public synthetic secrets.
[examples/v2-fixture.json](examples/v2-fixture.json) contains a fixed v2 envelope opened by three passkeys and one recovery key.
Both are generated by scripts/generate-fixture.mjs through a separate Node crypto implementation and remain unchanged during ordinary test runs.
The suite opens them through WebCrypto and opens new SDK output through Node crypto to catch derivation, field-order, tag, and encoding incompatibilities in either direction.
These checks validate the exercised format and do not constitute an independent cryptographic audit.
