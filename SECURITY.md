# Security boundary

This library protects encrypted bytes at rest when the envelope is copied without either unlocking secret.
It does not protect an unlocked page from XSS, malicious extensions, compromised application code, or a compromised device.
It does not implement account authentication, access control, credential registration, or authenticator attestation.
It has not received an independent security or cryptographic audit.

WebAuthn PRF support is optional and must be checked through the actual credential operation.
A capability advertisement alone does not establish that a particular credential can produce an output.
Changing the PRF evaluation input or selecting a different credential changes the derived secret.
Keep the persisted binding and an independently stored recovery secret available across domain, browser, and device changes.
The browser ceremony is intentionally separate from server-side assertion verification.
If an application also authenticates to a server, it must use its WebAuthn library to verify that separate authentication flow without forwarding PRF secrets.

The recovery secret provides full access to the payload and must be protected like a decryption key.
It is generated randomly, not derived from a short password.
Metadata includes every enrolled credential identifier (up to eight), the PRF input, random salts, and ciphertext size and is not confidential.
PRF output, recovery secrets, and plaintext must never enter telemetry, exception reports, URLs, or ordinary logs.

Parsing enforces field count, canonical encoding, exact key sizes, and payload limits before cryptographic operations.
Envelope, binding, and option records reject accessors, hidden properties, symbols, and non-data object prototypes; validation failures do not expose caller-supplied exception details.
JavaScript allocations and garbage collection prevent a guarantee of secret memory erasure.
The implementation clears owned temporary byte buffers on normal completion and failure, while callers retain responsibility for their own buffers and strings.
No filesystem or network operations are performed by the encryption library.
`requestPrf` invokes the browser's Credential Management API and therefore involves the configured authenticator or credential provider.
It rejects a cancellation observed after a provider returns instead of releasing the PRF result.

There is no anti-rollback service, shared-device isolation, forward secrecy, streaming encryption, or revocation of already downloaded ciphertext.
Every passkey added to a v2 envelope can unwrap its data key; revoking one requires resealing with a new data key, not deleting its slot.
Persisting an older valid envelope can restore an older state.
Opening an envelope using one secret does not verify that the other recovery method remains available.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub: https://github.com/hskl18/passkey-vault-kit/security/advisories/new
Please do not open a public issue or publish details before a fix is released.
Do not include real credential data, ciphertext from users, recovery keys, or production secrets in reports.
