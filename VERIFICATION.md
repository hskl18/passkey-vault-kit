# Verification record

This record lists what the current source has been checked against and what has not been checked.
It is not a security certification.

## Automated checks

`npm run check` builds the library and the browser workflow example with strict TypeScript settings and runs 50 behavioral cases:

- Both unlocking methods, wrong secrets, every authenticated metadata and ciphertext field, cross-envelope substitution, malformed envelopes, canonical encoding, RP ID normalization, caller-buffer ownership, and empty and 16 MiB payloads.
- Version 2 slot handling: upgrade through either secret with existing slots preserved, the eight-passkey limit, duplicate or mismatched bindings, a new output that already opens a slot, slot removal, reordering and substitution, and malformed slot arrays.
- `requestPrf` against a mocked Credential Management API: request parameters, fresh challenges, multi-credential requests, result copying, failures, invalid signals, and cancellation before, during, and racing with completion.
- The persisted v1 and v2 fixtures, produced by an independent Node crypto implementation of FORMAT.md, open through WebCrypto, and new SDK output of each version opens through that implementation.
- The HKDF reference matches RFC 5869 Appendix A.1.
- A real npm archive installs into an offline consumer, whose declarations compile with TypeScript 5.7.3 and 7.0.2.

The verified-notes HTTP suite has 14 cases.
An ephemeral ES256 fixture supplies real registration bytes and assertion signatures to the unmodified server verifier.
The cases cover changed signatures, challenge and origin failures, RP ID hash, missing user verification, replay, CSRF byte lengths, session rotation, and concurrent credential limits.

On 2026-10-26 both suites passed on macOS arm64 with Node.js 26.10.0.
CI runs `npm run check` on Ubuntu, macOS, and Windows with Node.js 22, 24, and 26, plus 22.13.0 on Ubuntu; the verified-notes suite runs on Ubuntu with Node.js 22, 24, and 26.

## Latest native browser run

On 2026-10-26, headless Chrome 156.0.8078.48 ran both browser suites with Playwright 1.64.1 and CDP CTAP2.1 virtual authenticators.
Each run used a fresh temporary profile, localhost only, synthetic data, and no account, keychain, or physical authenticator.

`test/browser` passed eight checks through the native Credential Management API and WebCrypto:

1. Registration requests PRF, confirms it is enabled, obtains 32 bytes, and seals binary data.
2. A reload reads the stored envelope and unlocks it with a fresh PRF evaluation.
3. After the old virtual credential is removed, recovery builds a new binding and pending envelope that old secrets cannot open.
4. A wrong recovery key cannot validate the pending record, and the original record stays recoverable.
5. The stored candidate opens through the new recovery key and a fresh PRF before it replaces the current record.
6. Another reload opens the committed replacement through its new binding and recovery key.
7. Aborting a pending request returns `ABORTED` without changing current or pending records.
8. A credential without PRF returns `PRF_UNAVAILABLE`, keeps the current record, and leaves recovery usable.

`integration/verified-notes/verify_browser.py` passed twelve application paths.
They cover registration and server-verified login, reload and PRF unlock, altered signatures and replay, and recovery without account authentication.
They also cover session refresh that keeps an unsaved draft, busy and pending locks, abandoned candidates, and a second passkey on a virtual USB key that joins the note, after which each authenticator unlocks it alone.

Both runners compare the served SDK bytes with the archive under test, confirm that browser storage holds only encrypted envelopes, and check that page requests never carry PRF outputs, recovery keys, or note text.

## Not yet verified

- Node.js 22 and 24 for this revision.
- Browsers other than Chrome, physical authenticators, and synced credential providers.
  Virtual authenticators do not establish support for a real browser and provider combination.
- An independent cryptographic audit of the implementation and envelope format.

See RELEASING.md before making a supported-release claim.
