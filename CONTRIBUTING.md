# Contributing

Keep this package focused on local encryption, explicit recovery, and a small framework-independent interface.
Account authentication, storage services, synchronisation, and UI belong in consuming applications.
No business-specific data, credentials, internal hostnames, or production ciphertext belongs in this repository.

## Development

Use Node.js 22.13 or newer and the checked-in npm lockfile.

```sh
npm ci --ignore-scripts
npm run check
npm run demo
npm pack --dry-run
```

`check` verifies strict library types, builds the package, checks the browser integration example, runs the Node test suite, and installs a real archive into an isolated offline consumer.
Use npm test to build and run behavior checks, npm run test:built to reuse an existing build, or npm run test:package for the archive and declaration check against that build.
The regression suite uses node:test and node:assert without a test-framework dependency.
Package consumption compiles the installed browser example with both TypeScript 5.7.3 and 7.0.2 using pinned development dependencies.
The maximum-payload case exercises the full 16 MiB limit and can take several seconds.
The demonstration uses synthetic key material and does not establish authenticator support.
Do not edit dist files or package-lock.json manually.
Regenerate build output with npm run build and dependency metadata with npm install.

## Persisted-format regression

The public synthetic examples/v1-fixture.json and examples/v2-fixture.json fix a durable v1 envelope and a v2 envelope with three passkeys, together with their known secrets.
Never use their public secrets to protect real data.
The generator uses a separate node:crypto implementation of FORMAT.md, not the production WebCrypto code.
The HKDF reference is also checked against RFC 5869 Appendix A.1.
Run npm run fixture:generate only when intentionally reviewing fixture generation; tests compare the persisted fixture with the generator without rewriting it.
Both SDK opening methods must continue to read these persisted formats, and the reference implementation must open new SDK output of each version.

## Review requirements

Describe the specific failure or user workflow the change addresses.
Changes to cryptographic key derivation, nonce generation, authenticated metadata, binary encoding, or envelope parsing require focused regression evidence and review against FORMAT.md.
An envelope change must retain the documented format or introduce a new format version and an explicit migration policy.
Do not silently weaken validation, remove recovery, or treat a signature as PRF output.
Describe behavior in Node and in a secure browser context separately.
An absent independent audit must remain visible in security and release documentation.

Use synthetic data and keys in examples and reports.
Report vulnerabilities privately as described in SECURITY.md.
Include reproduction instructions without actual secrets, user data, or ciphertext from users.

## Runtime and compatibility

The package is ESM and uses native WebCrypto without a Node-specific runtime import.
Its declarations require TypeScript 5.7 or newer for typed-array buffer types.
Browser integration requires the DOM library types.
No polyfill makes an unsupported authenticator support PRF.
No formatter is configured; match the surrounding style.
