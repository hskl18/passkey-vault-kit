import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import test from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));

test('actual npm archive installs offline and exposes usable ESM, types and fixtures', { timeout: 60000 }, async t => {
  const temporary = await mkdtemp(join(root, '.package-check.'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, 'Run this consumer check with npm run test:package');
  const env = { ...process.env, npm_config_cache: join(temporary, 'cache') };
  const run = (args, cwd = root) => execFileSync(process.execPath, args, {
    cwd, env, encoding: 'utf8', timeout: 45000, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const [packed] = JSON.parse(run([npmCli, 'pack', '--ignore-scripts', '--json', '--pack-destination', temporary]));
  const names = packed.files.map(file => file.path);
  assert.deepEqual(names.sort(), [
    'LICENSE', 'README.md', 'SECURITY.md', 'FORMAT.md',
    'package.json', 'dist/index.js', 'dist/index.d.ts',
    'examples/node-demo.mjs', 'examples/browser-workflow.ts', 'examples/v1-fixture.json', 'examples/v2-fixture.json',
  ].sort());
  let archive = join(temporary, packed.filename);
  if (process.env.PASSKEY_VAULT_PACKAGE_ARCHIVE) {
    const supplied = resolve(root, process.env.PASSKEY_VAULT_PACKAGE_ARCHIVE);
    const digest = async path => createHash('sha256').update(gunzipSync(await readFile(path), {
      maxOutputLength: 16 * 1024 * 1024,
    })).digest('hex');
    assert.equal(await digest(supplied), await digest(archive), 'Candidate archive must contain the checked source build');
    archive = supplied;
  }
  const consumer = join(temporary, 'consumer');
  run([npmCli, 'install', '--prefix', consumer, '--ignore-scripts', '--no-audit', '--no-fund', '--offline', archive]);
  run(['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import { readFile } from 'node:fs/promises';
    import * as sdk from 'passkey-vault-kit';
    const fixture = JSON.parse(await readFile('./node_modules/passkey-vault-kit/examples/v1-fixture.json', 'utf8'));
    const expected = Buffer.from(fixture.plaintext, 'base64url');
    assert.deepEqual(Buffer.from(await sdk.openWithRecovery(fixture.vault, fixture.recoveryKey)), expected);
    assert.deepEqual(Buffer.from(await sdk.openWithPrf(fixture.vault, Buffer.from(fixture.prfOutput, 'base64url'))), expected);
    const saved = sdk.serializeVault(fixture.vault);
    assert.deepEqual(sdk.parseVault(saved), fixture.vault);
    assert.equal(sdk.MAX_PLAINTEXT_BYTES, 16777216);
    assert.equal(typeof sdk.requestPrf, 'function');
    assert.equal(new sdk.VaultError('INVALID_INPUT').code, 'INVALID_INPUT');
  `], consumer);
  const packageRoot = join(consumer, 'node_modules', 'passkey-vault-kit');
  const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  assert.equal(metadata.type, 'module');
  assert.equal(metadata.license, 'MIT');
  assert.equal(metadata.dependencies, undefined);
  for (const [compiler, options] of [['typescript', ['--ignoreConfig']], ['typescript-5-7', []]]) {
    run([join(root, 'node_modules', compiler, 'bin', 'tsc'), ...options, '--noEmit',
      '--strict', '--module', 'NodeNext', '--target', 'ES2022', '--lib', 'ES2022,DOM',
      join(packageRoot, 'examples', 'browser-workflow.ts')]);
  }
});
