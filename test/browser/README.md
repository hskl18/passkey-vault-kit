# Anonymous native browser regression

This source-checkout test owns its localhost server, selects a free loopback port, and shuts the server and browser down when it finishes.
It needs no account, keychain, credential provider, or remote service.
The browser uses a fresh temporary headless profile and a CDP virtual authenticator.

Install Python 3.10 or newer and Google Chrome, then run from this project's root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r test/browser/requirements.txt
npm ci --ignore-scripts
npm run build
mkdir -p .artifacts
npm pack --ignore-scripts --pack-destination .artifacts
.venv/bin/python test/browser/verify_browser.py
```

Alternatively, activate the environment with `. .venv/bin/activate` and run `npm run test:browser`.
Use `--archive PATH` to check a particular retained npm archive and `--output PATH` to preserve a separate JSON result.
The defaults are `.artifacts/passkey-vault-kit-<version>.tgz`, using the `package.json` version, and `.artifacts/browser/result.json` inside this project, independent of the current working directory.
These browser dependencies and test sources are development-only and are excluded from the npm distribution.
The ordinary `npm run check` does not start a browser.
Run `.venv/bin/python -m unittest discover -s test/browser -p 'test_*.py'` for a server-lifecycle check that does not launch a browser.
It verifies that a simulated browser launch failure closes the owned server without writing a successful result.

Eight checks exercise PRF registration, reload, recovery after virtual credential deletion, failed replacement verification, verified replacement commit, rotated reload, cancellation, and lack of PRF support.
Every successful unlock compares binary bytes, and the failure paths preserve the prior encrypted record.
The server and runner compare archive, SDK, fixture, and HTML digests so a stale server cannot be attributed to a new archive.
Recovery secrets and PRF outputs stay out of result files; only the encrypted envelope remains in the temporary browser storage.

The result records the actual Chrome and Playwright versions, archive and harness hashes, and individual assertions.
Virtual-authenticator success does not establish physical-device, synced-provider, cross-device, storage-durability, recovery-key delivery, or independent cryptographic-audit coverage.
