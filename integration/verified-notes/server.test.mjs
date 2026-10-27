import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { once } from 'node:events';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createNotesServer } from './server.mjs';

async function setup(t, options) {
  const server = createNotesServer(options);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const port = server.address().port;
  const origin = `http://localhost:${port}`;
  async function call(path, { method = 'GET', headers = {}, body, session, pauseBody } = {}) {
    const bytes = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = request({ hostname: '127.0.0.1', port, method, path, headers: {
        Host: `localhost:${port}`,
        ...(bytes === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bytes) }),
        ...(session ? { Cookie: session.cookie, Origin: origin, 'X-CSRF-Token': session.csrfToken } : {}), ...headers,
      } }, (res) => {
        let body = '';
        res.setEncoding('utf8').on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          let json;
          try { json = JSON.parse(body); } catch {}
          resolve({ status: res.statusCode, headers: res.headers, body, json });
        });
      });
      req.on('error', reject);
      if (pauseBody) {
        req.flushHeaders();
        pauseBody.then(() => req.end(bytes), reject);
      } else req.end(bytes);
    });
  }
  const update = (result) => ({ ...result.json, cookie: result.headers['set-cookie']?.[0].split(';')[0] });
  const session = update(await call('/api/session'));
  const post = (path, body = {}, current = session, headers = {}) => call(path, { method: 'POST', body, session: current, headers });
  return { server, origin, call, post, session, update };
}

async function suspendedPost({ call, server, session }, path, body) {
  let release;
  const pauseBody = new Promise((resolve) => { release = resolve; });
  const receivedHeaders = once(server, 'request');
  const response = call(path, { method: 'POST', body, session, pauseBody });
  await receivedHeaders;
  return () => { release(); return response; };
}

const hash = (bytes) => createHash('sha256').update(bytes).digest();
const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
function cbor(value) {
  const head = (major, n) => n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  const entries = [...value.entries()];
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([key, entry]) => [cbor(key), cbor(entry)])]);
}

// An independent ephemeral ES256 authenticator fixture, without mocking either server verifier.
function authenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const id = randomBytes(32);
  let counter = 0;
  const clientData = (type, challenge, origin) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    registration(options, origin) {
      const key = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
      const length = Buffer.alloc(2); length.writeUInt16BE(id.length);
      const authData = Buffer.concat([hash(Buffer.from('localhost')), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, id, key]);
      const attestation = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
      return { id: b64(id), rawId: b64(id), type: 'public-key', response: { clientDataJSON: b64(clientData('webauthn.create', options.challenge, origin)), attestationObject: b64(attestation), transports: ['internal'] }, clientExtensionResults: {} };
    },
    assertion(options, origin, { challenge = options.challenge, clientOrigin = origin, rpId = 'localhost', flags = 0x05, corrupt = false } = {}) {
      const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
      const authenticatorData = Buffer.concat([hash(Buffer.from(rpId)), Buffer.from([flags]), count]);
      const client = clientData('webauthn.get', challenge, clientOrigin);
      const signature = sign('sha256', Buffer.concat([authenticatorData, hash(client)]), privateKey);
      if (corrupt) signature[signature.length - 1] ^= 1;
      return { id: b64(id), rawId: b64(id), type: 'public-key', response: { clientDataJSON: b64(client), authenticatorData: b64(authenticatorData), signature: b64(signature) }, clientExtensionResults: {} };
    },
  };
}

test('localhost-only Host, local static resources, HEAD and CSP', async (t) => {
  const { call } = await setup(t);
  for (const path of ['/', '/app.js', '/style.css', '/vendor/simplewebauthn.js', '/vendor/vault.js']) {
    const result = await call(path);
    assert.equal(result.status, 200, path);
    assert.match(result.headers['content-security-policy'], /default-src 'none'/);
    assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal((await call(path, { method: 'HEAD' })).body, '');
  }
  assert.equal((await call('/', { headers: { Host: 'evil.invalid' } })).status, 403);
  assert.equal((await call('/', { headers: { Host: '127.0.0.1' } })).status, 403);
  assert.equal((await call('/missing')).status, 404);
});

test('Origin, CSRF and unauthenticated authorization boundaries', async (t) => {
  const { post, session } = await setup(t);
  for (const origin of ['', 'null', 'https://evil.invalid']) {
    const result = await post('/api/register/options', {}, session, { Origin: origin });
    assert.equal(result.status, 403);
    assert.equal(result.json.error.code, 'ORIGIN_REJECTED');
  }
  for (const csrf of ['', 'forged', 'é'.repeat(43)]) {
    const result = await post('/api/register/options', {}, session, { 'X-CSRF-Token': csrf });
    assert.equal(result.status, 403);
    assert.equal(result.json.error.code, 'CSRF_REJECTED');
  }
  assert.equal((await post('/api/authorize')).status, 401);
  assert.equal((await post('/api/login/options')).json.error.code, 'NO_CREDENTIALS');
  assert.equal((await post('/api/authorize', { recoveryKey: 'synthetic-marker' })).json.error.code, 'UNEXPECTED_FIELD');
});

test('session cookie is HttpOnly/SameSite and bounded request parsing rejects data', async (t) => {
  const { call, post, session } = await setup(t);
  const issued = await call('/api/session');
  assert.match(issued.headers['set-cookie'][0], /HttpOnly; SameSite=Strict; Path=\//);
  assert.equal((await post('/api/register/options', '{')).json.error.code, 'INVALID_JSON');
  assert.equal((await post('/api/register/options', 'x'.repeat(65537))).status, 413);
  assert.equal((await post('/api/register/options', {}, session, { 'Content-Type': 'text/plain' })).status, 415);
  const result = await post('/api/register/options', { plaintext: 'synthetic-private-marker' });
  assert.equal(result.status, 400);
  assert.equal(result.body.includes('synthetic-private-marker'), false);
});

test('single-use challenge, session binding, replacement and expiry', async (t) => {
  let clock = 1000;
  const { post, call, session, update, origin } = await setup(t, { now: () => clock, challengeTtlMs: 100, sessionTtlMs: 1000 });
  const first = (await post('/api/register/options')).json;
  const second = (await post('/api/register/options')).json;
  assert.notEqual(first.challenge, second.challenge);
  assert.equal(second.authenticatorSelection.userVerification, 'required');
  assert.equal(second.authenticatorSelection.residentKey, 'required');
  assert.deepEqual(second.extensions.prf, {});
  const fixture = authenticator();
  const oldResponse = fixture.registration(first, origin);
  const other = update(await call('/api/session'));
  assert.equal((await post('/api/register/verify', oldResponse, other)).status, 409);
  assert.equal((await post('/api/register/verify', oldResponse)).json.error.code, 'VERIFICATION_FAILED');
  assert.equal((await post('/api/register/verify', oldResponse)).status, 409);
  const next = (await post('/api/register/options')).json;
  clock += 101;
  assert.equal((await post('/api/register/verify', fixture.registration(next, origin))).status, 409);
  clock += 1000;
  assert.equal((await post('/api/register/options', {}, session)).status, 401);
});

test('session cap and TTL are enforced without an HTTP clock or verification bypass', async (t) => {
  let clock = 0;
  const { call } = await setup(t, { now: () => clock, sessionTtlMs: 100, maxSessions: 2 });
  assert.equal((await call('/api/session')).status, 200);
  assert.equal((await call('/api/session')).json.error.code, 'SESSION_LIMIT');
  clock = 101;
  assert.equal((await call('/api/session')).status, 200);
  assert.equal((await call('/api/test/clock', { method: 'POST', body: {} })).status, 404);
});

test('real ES256 verification authenticates, rejects altered ceremony invariants and prevents replay', async (t) => {
  const { post, origin, session, update, call } = await setup(t);
  const fixture = authenticator();
  const registrationOptions = (await post('/api/register/options')).json;
  const registered = await post('/api/register/verify', fixture.registration(registrationOptions, origin));
  assert.equal(registered.status, 200, registered.body);
  let current = update(registered);
  assert.equal(current.authenticated, true);
  assert.notEqual(current.cookie, session.cookie);
  assert.equal((await post('/api/authorize', {}, session)).status, 401);
  assert.equal((await post('/api/authorize', {}, current)).status, 200);
  current = update(await post('/api/logout', {}, current));
  assert.equal(current.authenticated, false);
  for (const alteration of [{ corrupt: true }, { clientOrigin: 'https://evil.invalid' }, { challenge: 'wrong-challenge' }, { rpId: 'evil.invalid' }, { flags: 0x01 }]) {
    const options = (await post('/api/login/options', {}, current)).json;
    assert.equal(options.userVerification, 'required');
    assert.equal(options.extensions?.prf, undefined);
    const response = fixture.assertion(options, origin, alteration);
    const result = await post('/api/login/verify', response, current);
    assert.equal(result.status, 400, JSON.stringify(alteration));
    assert.equal(result.json.error.code, 'VERIFICATION_FAILED');
    assert.equal((await post('/api/login/verify', response, current)).status, 409);
    const state = await call('/api/session', { headers: { Cookie: current.cookie } });
    assert.equal(state.json.authenticated, false);
  }
  const options = (await post('/api/login/options', {}, current)).json;
  const response = fixture.assertion(options, origin);
  const loggedIn = await post('/api/login/verify', response, current);
  assert.equal(loggedIn.status, 200, loggedIn.body);
  current = update(loggedIn);
  assert.equal(current.authenticated, true);
  assert.equal(current.credentialId, registered.json.credentialId);
  assert.equal((await post('/api/login/verify', response, current)).status, 409);
});

test('PRF outputs and recovery fields are rejected by ceremony endpoints', async (t) => {
  const { post, origin } = await setup(t);
  const fixture = authenticator();
  const options = (await post('/api/register/options')).json;
  const body = fixture.registration(options, origin);
  body.clientExtensionResults = { prf: { results: { first: 'synthetic-private-marker' } } };
  const result = await post('/api/register/verify', body);
  assert.equal(result.status, 400);
  assert.equal(result.json.error.code, 'UNEXPECTED_FIELD');
  assert.equal(result.body.includes('synthetic-private-marker'), false);
  assert.equal((await post('/api/register/verify', body)).status, 409);
});

test('concurrent verification cannot exceed the eight-credential per-identity limit', async (t) => {
  const { post, origin, session, update, call } = await setup(t);
  const anchor = authenticator();
  let current = session;
  for (let index = 0; index < 7; index++) {
    const options = (await post('/api/register/options', {}, current)).json;
    const result = await post('/api/register/verify', (index === 0 ? anchor : authenticator()).registration(options, origin), current);
    assert.equal(result.status, 200, result.body);
    current = update(result);
  }
  const active = [];
  for (let index = 0; index < 2; index++) {
    const anonymous = update(await call('/api/session'));
    const options = (await post('/api/login/options', {}, anonymous)).json;
    active.push(update(await post('/api/login/verify', anchor.assertion(options, origin), anonymous)));
  }
  const options = await Promise.all(active.map((owner) => post('/api/register/options', {}, owner)));
  assert.ok(options.every((result) => result.status === 200));
  const results = await Promise.all(active.map((owner, index) => post('/api/register/verify', authenticator().registration(options[index].json, origin), owner)));
  assert.deepEqual(results.map((result) => result.status).sort(), [200, 409]);
  assert.equal(results.find((result) => result.status === 409).json.error.code, 'CREDENTIAL_LIMIT');
  assert.equal((await post('/api/register/options', {}, current)).json.error.code, 'CREDENTIAL_LIMIT');
});

test('concurrent verification cannot exceed the 256-credential global limit', async (t) => {
  const { post, origin, session, update, call } = await setup(t);
  let current = session;
  for (let index = 0; index < 255; index++) {
    const options = (await post('/api/register/options', {}, current)).json;
    const registered = await post('/api/register/verify', authenticator().registration(options, origin), current);
    assert.equal(registered.status, 200, registered.body);
    current = update(await post('/api/logout', {}, update(registered)));
  }
  const active = [current, update(await call('/api/session'))];
  const options = await Promise.all(active.map((owner) => post('/api/register/options', {}, owner)));
  assert.ok(options.every((result) => result.status === 200));
  const results = await Promise.all(active.map((owner, index) => post('/api/register/verify', authenticator().registration(options[index].json, origin), owner)));
  assert.deepEqual(results.map((result) => result.status).sort(), [200, 409]);
  assert.equal(results.find((result) => result.status === 409).json.error.code, 'CREDENTIAL_LIMIT');
});

test('logout revokes an in-flight registration before its body finishes', async (t) => {
  const context = await setup(t);
  const { post, session, update, origin } = context;
  const options = (await post('/api/register/options')).json;
  const finish = await suspendedPost(context, '/api/register/verify', authenticator().registration(options, origin));
  const loggedOut = await post('/api/logout');
  assert.equal(loggedOut.status, 200);
  const stale = await finish();
  assert.equal(stale.status, 401, stale.body);
  assert.equal(stale.json.error.code, 'SESSION_REQUIRED');
  assert.equal(stale.headers['set-cookie'], undefined);
  assert.equal((await post('/api/login/options', {}, update(loggedOut))).json.error.code, 'NO_CREDENTIALS');
  assert.equal((await post('/api/authorize', {}, session)).status, 401);
});

test('logout revokes an in-flight login before its body finishes', async (t) => {
  const context = await setup(t);
  const { post, origin, update } = context;
  const fixture = authenticator();
  const registration = (await post('/api/register/options')).json;
  const owner = update(await post('/api/register/verify', fixture.registration(registration, origin)));
  const anonymous = update(await post('/api/logout', {}, owner));
  const options = (await post('/api/login/options', {}, anonymous)).json;
  const finish = await suspendedPost({ ...context, session: anonymous }, '/api/login/verify', fixture.assertion(options, origin));
  const loggedOut = await post('/api/logout', {}, anonymous);
  const stale = await finish();
  assert.equal(stale.status, 401, stale.body);
  assert.equal(stale.json.error.code, 'SESSION_REQUIRED');
  assert.equal(stale.headers['set-cookie'], undefined);
  assert.equal((await post('/api/authorize', {}, update(loggedOut))).status, 401);
});

test('session and challenge TTLs are rechecked after a delayed verification body', async (t) => {
  for (const boundary of ['session', 'challenge']) {
    let clock = 0;
    const context = await setup(t, { now: () => clock, sessionTtlMs: boundary === 'session' ? 10 : 100, challengeTtlMs: 10 });
    const { post, origin } = context;
    const options = (await post('/api/register/options')).json;
    const finish = await suspendedPost(context, '/api/register/verify', authenticator().registration(options, origin));
    clock = 11;
    const expired = await finish();
    assert.equal(expired.status, boundary === 'session' ? 401 : 409, `${boundary}: ${expired.body}`);
    assert.equal(expired.json.error.code, boundary === 'session' ? 'SESSION_REQUIRED' : 'CHALLENGE_UNAVAILABLE');
    assert.equal(expired.headers['set-cookie'], undefined);
  }
});

test('successful session rotation cannot be undone by an older in-flight registration', async (t) => {
  const context = await setup(t);
  const { post, origin, update } = context;
  const oldOptions = (await post('/api/register/options')).json;
  const older = authenticator();
  const finish = await suspendedPost(context, '/api/register/verify', older.registration(oldOptions, origin));
  const currentOptions = (await post('/api/register/options')).json;
  const current = authenticator();
  const registered = await post('/api/register/verify', current.registration(currentOptions, origin));
  assert.equal(registered.status, 200, registered.body);
  const stale = await finish();
  assert.equal(stale.status, 401, stale.body);
  assert.equal(stale.headers['set-cookie'], undefined);
  const anonymous = update(await post('/api/logout', {}, update(registered)));
  const options = (await post('/api/login/options', {}, anonymous)).json;
  assert.equal((await post('/api/login/verify', older.assertion(options, origin), anonymous)).status, 400);
});

test('new options supersede an in-flight challenge without consuming the replacement', async (t) => {
  const context = await setup(t);
  const { post, origin } = context;
  const oldOptions = (await post('/api/register/options')).json;
  const finish = await suspendedPost(context, '/api/register/verify', authenticator().registration(oldOptions, origin));
  const replacement = (await post('/api/register/options')).json;
  const stale = await finish();
  assert.equal(stale.status, 409, stale.body);
  assert.equal(stale.json.error.code, 'CHALLENGE_UNAVAILABLE');
  assert.equal(stale.headers['set-cookie'], undefined);
  const accepted = await post('/api/register/verify', authenticator().registration(replacement, origin));
  assert.equal(accepted.status, 200, accepted.body);
});
