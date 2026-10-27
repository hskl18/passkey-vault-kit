# Release preparation

This is the maintainer checklist for a release.
The package has not yet been published or had an independent cryptographic audit.
Do not label it audited, production-proven, or compatible with every passkey provider.

## Release gates

1. Run npm ci --ignore-scripts and npm run check from the exact source revision being released.
2. Confirm the automated regressions included in npm run check cover wrong secrets, malformed envelopes, metadata and ciphertext tampering, recovery, mocked cancellation, resource boundaries, and exported API behavior.
3. Review the persisted public fixture and independent Node crypto validation against FORMAT.md; do not regenerate a fixture merely to make an incompatible implementation pass.
4. Run the Node demonstration and package-consumer installation check.
5. Verify actual browser and authenticator combinations before listing them as supported.
6. Inspect npm pack output and ensure no keys, environment files, local envelopes, verification scratch files, or unrelated source files are included.
7. Review dependency advisories and third-party licensing.
8. Confirm private vulnerability reporting is enabled on the GitHub repository.
9. Confirm the package name, repository metadata, version, and license attribution before publication.

The crypto review and authenticator checks are separate from build and package checks.
Record exactly which gates were completed, on which revision, and which remain unverified.

## Compatibility

Envelope versions 1 and 2 specify the complete input to key derivation and authenticated encryption in FORMAT.md.
Any incompatible persisted-format change requires a new envelope version.
Unsupported versions and suites fail explicitly instead of attempting a fallback.
The first public release must include example envelopes and durable regression coverage for every declared format; `examples/v1-fixture.json` and `examples/v2-fixture.json` cover versions 1 and 2.

Before a public release, the npm package version is a development version and does not imply that these gates have passed.

For the source-only verified-notes integration, build and retain the SDK archive, install its separate locked dependencies with `npm ci --ignore-scripts --prefix integration/verified-notes`, and run `npm run test:integration`.
Its optional native browser trial uses the development environment documented in `integration/verified-notes/README.md`.
CI also runs the HTTP integration on Ubuntu with Node.js 22, 24 and 26.

## Package inspection

```sh
npm run check
npm pack --dry-run
npm pack
```

Install the resulting archive into a disposable consumer using npm install --ignore-scripts with a local archive path.
Verify imports, declarations, and the packaged demonstration in that consumer.
Set PASSKEY_VAULT_PACKAGE_ARCHIVE to the candidate path when running npm run test:package to install that exact archive and compare its decompressed tar digest with the current pack output.
Compressed archive checksums can differ between Node zlib versions even when the tar content is identical, so record the candidate's own SHA-256 separately.
