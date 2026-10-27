# Verified local notes

This runnable example connects native browser WebAuthn registration and login, server verification, and Passkey Vault Kit encrypted browser notes.
Registration and authentication use `@simplewebauthn/server` 14.0.3 and the locally installed `@simplewebauthn/browser` 14.0.0 UMD bundle.
The Vault browser module is read from a real retained npm archive of this source project.
No CDN, bundler, account service, or real database is required.

The example is MIT licensed.
It is a local synthetic integration, not a production account or storage service.
The Vault cryptography and physical authenticator/provider interoperability still require their separate review and rollout evidence.

## Run from this source checkout

Requirements are Node.js 22.13 or newer, npm, a POSIX `tar` command, and a browser/provider capable of WebAuthn with user verification and the PRF extension.
`localhost` HTTP is used as the browser's local secure-context exception.
Always open the printed `http://localhost:PORT` URL, rather than its numeric IP address.

From the Vault source root:

```sh
npm ci --ignore-scripts
npm run build
npm pack
cd integration/verified-notes
npm ci --ignore-scripts
npm test
npm start
```

The server binds only `127.0.0.1` and defaults to port 8787.
It prints one JSON line containing `origin` and `port`, without credential or request-body logging.
Use `PORT=0 npm start` for a free port.
Browser storage belongs to an exact origin, including its port.
Restarting with `PORT=0` can choose a different origin, whose storage will not contain the old encrypted envelope.
To unlock or recover the retained note, reopen the same localhost origin and port; use a stable port such as the default 8787 for a notebook you intend to retain.
Stop it with Ctrl-C.
Dependencies are locked by this directory's own private package and npm-generated lockfile; they are not added to the Vault SDK runtime dependencies.

The default archive is `passkey-vault-kit-<version>.tgz` for the version in the Vault `package.json`, in the Vault source root, as created by `npm pack` above.
If it is absent, the server tries the same filename under the root `.artifacts` directory.
To select exact archive bytes explicitly, run:

```sh
node server.mjs --archive /absolute/path/passkey-vault-kit-<version>.tgz
```

`VAULT_ARCHIVE` is the corresponding environment option.
The server reads only `package/dist/index.js` from that archive using `tar -xOf`; it does not extract files to disk or import another checkout's SDK implementation.
The browser helper is served from this directory's installed npm package, without external resource requests.
Do not distribute `node_modules`, browser profiles, recovery keys, plaintext notes, or private runtime artifacts with this source.

## Exercise the application

1. Open the printed localhost URL and choose **Register passkey**.
   Complete the native credential prompt with user verification.
   The server verifies the registration's challenge, origin, RP ID and UV before establishing the synthetic authenticated session.
   Registration requests a resident credential and `prf: {}`; no PRF evaluation output is requested in that server ceremony.
2. Edit the initial synthetic note and choose **Encrypt a candidate**.
   The browser first checks the server session, then evaluates PRF locally and seals the note with the archive's actual Vault SDK.
   It stores a separate encrypted candidate and reopens that stored copy through both PRF and recovery before continuing.
   Editing is locked while an operation is busy.
   While the candidate awaits confirmation, editing, registration, login, passkey unlock and recovery are locked so the displayed note remains the candidate's snapshot.
   Logout remains available to abandon the pending in-memory candidate while retaining encrypted storage.
3. Save the displayed new recovery key independently, re-enter it in the confirmation field, then choose **Confirm key and save encrypted note**.
   Only that confirmation replaces the current saved encrypted envelope.
   If the saved note has other passkeys, the pending section warns that saving removes them, because a new envelope has a new data key; add them again afterwards.
   The key is not placed in browser storage or an HTTP request.
   A failed candidate operation or failed replacement leaves the old saved envelope in place.
4. Reload the page.
   The note starts blank while its encrypted envelope remains saved.
   Choose **Unlock saved note with passkey** to perform a fresh browser-local PRF evaluation and open the envelope.
5. Choose **Log out and clear plaintext**.
   The server rotates to an anonymous session; the page clears note and recovery-key fields and drops its in-memory candidate key.
   Saved and pending encrypted envelopes remain in browser storage.
   Choose **Log in** to complete a separate native authentication assertion whose signature the server verifies, then unlock locally.
6. While logged out, enter the independently saved recovery key and choose **Recover saved note locally**.
   Recovery can decrypt the saved envelope without any server request or credential operation.
   It does not authenticate the account or create, replace, or remove server credentials.
7. While logged in, choose **Register passkey** again to add a second credential, such as another device, to the same synthetic identity.
   Then choose **Add this passkey to the saved note**.
   The browser asks for the newly registered passkey, then for one that already opens the note, and writes a v2 envelope with both.
   The stored copy must open through both passkeys before it replaces the saved note; the recovery key is unchanged.
   **Unlock saved note with passkey** then offers every passkey on the note in one prompt.

Unsupported PRF, dismissed prompts, wrong recovery keys, tampered envelopes, verification failures and storage failures produce visible error states.
They do not silently substitute a credential ID, signature, password or session token for PRF output.
If a session expires, the server restarts, or its CSRF token changes, the next rejected session-dependent operation fetches a fresh session and token without automatically replaying the POST.
The visible `SESSION_CHANGED` state preserves the displayed draft, pending candidate and saved encrypted envelope and explicitly says that displayed unsaved content is still unsaved.
Register or log in again before retrying, rather than reloading and losing an unsaved draft.
If the server is temporarily unreachable during refresh, reconnect before retrying; no draft or encrypted state is cleared by that refresh failure.
An incomplete pending candidate after a reload is not automatically promoted; the previous committed envelope remains the saved note.
JavaScript cannot guarantee erasure of immutable strings or copies retained by the browser; the logout action clears the page's owned fields and buffers rather than claiming complete browser-memory sanitization.

## Data and trust boundaries

The server keeps synthetic credential public keys, counters, identity IDs, sessions and pending challenges only in memory.
Restarting it loses those login records.
The independently saved recovery key can still open a retained encrypted envelope locally, after which a newly registered passkey can reseal the recovered note.
The browser must retain the corresponding encrypted envelope; localStorage eviction or deletion can lose it.

The server accepts only its exact localhost Host and Origin, uses HttpOnly SameSite=Strict session cookies, and requires a per-session CSRF token for every POST.
The local HTTP cookie omits Secure because this example is served over loopback HTTP.
There are at most 64 sessions, with fixed 15-minute TTLs and at most one pending two-minute challenge per session.
Each verification attempt consumes its session's challenge before parsing the ceremony body; expired, replaced and repeated challenges fail.
After asynchronous body reads, options generation and verification, the server rechecks that the same session is still active and unexpired before changing credentials, counters or session identity.
Logout or another successful session rotation revokes older in-flight requests, and a newer options request supersedes an older in-flight challenge.
Successful registration and login rotate the session ID and CSRF token.
No HTTP route changes the clock, injects a verifier or bypasses authentication.

Request bodies are limited to 64 KiB and must be JSON objects with the endpoint's allowed fields.
The credential inventory is limited to 256 globally and eight per synthetic identity, checked both when issuing options and synchronously after verification before insertion.
Authentication requires a stored credential and an actual verified signature, expected challenge, expected origin, RP ID and UV; counters are updated after success.
Attestation preference is `none`, so registration does not claim hardware provenance or attestation trust.
The server does not treat an independently supplied recovery key as account authentication.

The client explicitly projects safe WebAuthn ceremony fields before each request.
PRF output, recovery keys and note plaintext are never sent to the server; extension outputs and unknown fields are rejected by ceremony endpoints.
Notes are stored only as encrypted Vault envelopes under `verified-notes.envelope.v1` and, while staged, `verified-notes.pending.v1`.
The app uses no external resources and sends no telemetry.
The static Content Security Policy permits only same-origin scripts, styles and connections and prevents framing.

The example relies on Web Storage's single-value replacement behavior and checks that its pending candidate and prior saved value are unchanged before committing.
It does not provide a multi-tab storage transaction, browser-eviction protection, durable backups, recovery-key delivery, a production account lifecycle, or protection from malicious same-origin code and extensions.
Do not infer these properties from successful encryption or a passing local ceremony.

## HTTP and page contract

`createNotesServer(options)` exported by `server.mjs` returns an unstarted native Node HTTP server.
Call `server.listen(0, '127.0.0.1')` in an isolated local runner, then derive the expected browser origin from its assigned port.
The optional `now`, `challengeTtlMs`, `sessionTtlMs` and `maxSessions` constructor parameters support bounded Node tests; they are never accepted through HTTP.
Direct CLI startup chooses its port from `PORT` and always binds loopback.

| Endpoint | Result |
| --- | --- |
| `GET /api/session` | Creates or reads the temporary session and returns `csrfToken`, `authenticated`, `credentialId`, and `rpId`. |
| `POST /api/register/options` with `{}` | Returns server-issued JSON registration options. |
| `POST /api/register/verify` | Verifies the projected registration response and returns `verified: true` plus the rotated authenticated session view. |
| `POST /api/login/options` with `{}` | Returns discoverable-credential authentication options; no PRF evaluation. |
| `POST /api/login/verify` | Verifies the assertion signature and returns `verified: true` plus the rotated authenticated session view. |
| `POST /api/authorize` with `{}` | Returns `authorized: true` only for an authenticated session. |
| `POST /api/logout` with `{}` | Rotates to an anonymous session without modifying credential inventory. |

All POSTs require the session cookie, exact `Origin`, JSON content type and `X-CSRF-Token`.
Errors are JSON `{ "error": { "code": "...", "message": "..." } }` with a non-success HTTP status.
Common codes include `HOST_REJECTED`, `ORIGIN_REJECTED`, `CSRF_REJECTED`, `SESSION_REQUIRED`, `AUTHENTICATION_REQUIRED`, `CHALLENGE_UNAVAILABLE`, `VERIFICATION_FAILED`, `BODY_TOO_LARGE` and `CREDENTIAL_LIMIT`.
GET and HEAD serve the local static resources; no service worker or externally fetched module is required.

The public controls have IDs `register`, `login`, `encrypt`, `unlock`, `add-passkey`, `recover`, `logout`, `note`, `recovery-key`, `new-recovery-key`, `save-recovery`, `confirm-recovery`, `pending-warning`, `status` and `error`.
Status is announced through an ARIA live region, errors through an alert, and inputs have explicit labels.
There are no test-only page methods or exposed secret state objects.

## Verification

`npm test` runs Node HTTP boundary regressions without starting a browser.
They exercise Host and Origin rejection, CSRF including Unicode byte-length cases, cookies, unauthenticated calls, request limits, challenge expiry/replacement/single use, session limits and concurrent credential-capacity checks.
An independently constructed ephemeral ES256 authenticator fixture supplies real keys, attestation-format-none registration bytes and signed assertions to the unmodified server verifiers.
Correct signatures authenticate; altered signatures, client origin, challenge, RP ID hash, missing UV and replay fail.
That fixture is not evidence of native browser/provider compatibility and never replaces the verifier with a mock.

Native browser acceptance is separate from these Node tests.
Use only a synthetic virtual authenticator or a deliberately chosen non-production credential; physical/provider coverage and production account security are outside this example.

The source checkout includes `verify_browser.py` for an anonymous trial with a fresh headless Chrome profile and a CDP virtual authenticator.
After the source-root build and archive creation above, run these commands from the Vault source root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r test/browser/requirements.txt
.venv/bin/python integration/verified-notes/verify_browser.py
```

Google Chrome and Python 3.10 or newer are required.
The runner owns an ephemeral loopback server, restricts page traffic to that origin, compares served SDK bytes to the chosen archive, and closes its browser and server in finally blocks.
It checks native registration and signed login, changed signatures and replay, encrypted candidate confirmation, reload, logout, independent recovery, a lost session with draft preservation, pending-state controls, and a second passkey on a virtual USB key joining the note.
Losing the temporary session cookie exercises the front-end session refresh path; actual TTL expiry is covered separately by the Node HTTP tests.
The JSON result contains archive, SDK and harness hashes without recovery keys, PRF outputs, note plaintext or credential response bodies.
The saved screenshot is taken only after logout has cleared the page's secret fields.
This runner is optional and the ordinary SDK check does not start a browser.

## References

- [SimpleWebAuthn server 14.0.x documentation](https://simplewebauthn.dev/docs/packages/server) describes challenge/origin/RP ID verification and credential counter storage.
- [SimpleWebAuthn browser 14.0.x documentation](https://simplewebauthn.dev/docs/packages/browser) describes native registration/authentication and its UMD bundle.
- [Vault usage](../../README.md#use) documents PRF registration, evaluation, independent recovery and staged replacement.
