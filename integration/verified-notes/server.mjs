import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';

const here = dirname(fileURLToPath(import.meta.url));
const vaultRoot = resolve(here, '../..');
const archiveName = `passkey-vault-kit-${JSON.parse(readFileSync(join(vaultRoot, 'package.json'), 'utf8')).version}.tgz`;
const cookieName = 'verified_notes_session';
const token = () => randomBytes(32).toString('base64url');
const bodyLimit = 64 * 1024;

class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

function sdkFromArchive(archive) {
  const file = resolve(archive ?? (existsSync(join(vaultRoot, archiveName))
    ? join(vaultRoot, archiveName) : join(vaultRoot, '.artifacts', archiveName)));
  if (!existsSync(file)) throw new Error(`Run "npm run build && npm pack" in the repository root first (expected ${archiveName}).`);
  if (!statSync(file).isFile() || statSync(file).size > 10 * 1024 * 1024) throw new Error('Use a regular Vault npm archive below 10 MiB.');
  return execFileSync('tar', ['-xOf', file, 'package/dist/index.js'], { maxBuffer: 256 * 1024 });
}

async function readJson(req) {
  if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') throw new HttpError(415, 'JSON_REQUIRED', 'Send application/json.');
  if (Number(req.headers['content-length']) > bodyLimit) throw new HttpError(413, 'BODY_TOO_LARGE', 'The request is too large.');
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > bodyLimit) throw new HttpError(413, 'BODY_TOO_LARGE', 'The request is too large.');
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw new HttpError(400, 'INVALID_JSON', 'Send a JSON object.'); }
}

function emptyBody(body) {
  if (Object.keys(body).length !== 0) throw new HttpError(400, 'UNEXPECTED_FIELD', 'This endpoint accepts an empty object.');
}

function ceremonyBody(body, kind) {
  const allowed = ['id', 'rawId', 'type', 'response', 'clientExtensionResults', 'authenticatorAttachment'];
  const responseFields = kind === 'register' ? ['clientDataJSON', 'attestationObject', 'transports'] : ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle'];
  if (Object.keys(body).some((key) => !allowed.includes(key)) || !body.response || typeof body.response !== 'object' || Array.isArray(body.response)
    || Object.keys(body.response).some((key) => !responseFields.includes(key))
    || !body.clientExtensionResults || typeof body.clientExtensionResults !== 'object' || Array.isArray(body.clientExtensionResults)
    || Object.keys(body.clientExtensionResults).length !== 0) {
    throw new HttpError(400, 'UNEXPECTED_FIELD', 'Only the WebAuthn ceremony fields are accepted; extension outputs stay in the browser.');
  }
}

export function createNotesServer({ archive = process.env.VAULT_ARCHIVE, now = Date.now, challengeTtlMs = 120_000, sessionTtlMs = 900_000, maxSessions = 64 } = {}) {
  const sessions = new Map();
  const credentials = new Map();
  const browserRoot = resolve(dirname(fileURLToPath(import.meta.resolve('@simplewebauthn/browser'))), '..');
  const staticFiles = new Map([
    ['/', ['text/html; charset=utf-8', readFileSync(join(here, 'index.html'))]],
    ['/app.js', ['text/javascript; charset=utf-8', readFileSync(join(here, 'app.js'))]],
    ['/style.css', ['text/css; charset=utf-8', readFileSync(join(here, 'style.css'))]],
    ['/vendor/simplewebauthn.js', ['text/javascript; charset=utf-8', readFileSync(join(browserRoot, 'dist/bundle/index.umd.min.js'))]],
    ['/vendor/vault.js', ['text/javascript; charset=utf-8', sdkFromArchive(archive)]],
  ]);
  const server = createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    route(req, res).catch((error) => {
      if (res.headersSent) { res.destroy(); return; }
      send(res, error instanceof HttpError ? error.status : 500, {
        error: { code: error instanceof HttpError ? error.code : 'INTERNAL_ERROR', message: error instanceof HttpError ? error.message : 'The local example could not complete this request.' },
      });
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;

  const origin = () => new URL(`http://localhost:${server.address().port}`).origin;
  const view = (session) => ({ csrfToken: session.csrf, authenticated: Boolean(session.userId), credentialId: session.credentialId ?? null, rpId: 'localhost' });
  function send(res, status, value) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(value));
  }
  function newSession(res, userId, credentialId) {
    for (const [id, session] of sessions) if (session.expires <= now()) sessions.delete(id);
    if (sessions.size >= maxSessions) throw new HttpError(503, 'SESSION_LIMIT', 'The local session limit was reached; wait for sessions to expire.');
    const session = { id: token(), csrf: token(), expires: now() + sessionTtlMs, userId, credentialId, pending: null, challengeRevision: 0 };
    sessions.set(session.id, session);
    res.setHeader('Set-Cookie', `${cookieName}=${session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.ceil(sessionTtlMs / 1000)}`);
    return session;
  }
  function findSession(req) {
    const matches = (req.headers.cookie ?? '').split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${cookieName}=`));
    if (matches.length !== 1) return null;
    const id = matches[0].slice(cookieName.length + 1);
    const session = sessions.get(id);
    if (!session) return null;
    if (session.expires <= now()) { sessions.delete(id); return null; }
    return session;
  }
  function rotateSession(session, res, userId, credentialId) {
    assertActiveSession(session);
    sessions.delete(session.id);
    return newSession(res, userId, credentialId);
  }
  function assertActiveSession(session) {
    if (sessions.get(session.id) !== session || session.expires <= now()) {
      if (sessions.get(session.id) === session) sessions.delete(session.id);
      throw new HttpError(401, 'SESSION_REQUIRED', 'Refresh this page to begin a local session.');
    }
  }
  function assertCurrentChallenge(session, pending) {
    assertActiveSession(session);
    if (pending.expires <= now() || pending.revision !== session.challengeRevision) throw new HttpError(409, 'CHALLENGE_UNAVAILABLE', 'The challenge expired, was replaced, or was already used. Start again.');
  }
  function takeChallenge(session, kind) {
    const pending = session.pending;
    session.pending = null;
    if (!pending || pending.kind !== kind) throw new HttpError(409, 'CHALLENGE_UNAVAILABLE', 'The challenge expired, was replaced, or was already used. Start again.');
    assertCurrentChallenge(session, pending);
    return pending;
  }
  async function route(req, res) {
    if (req.socket.localAddress !== '127.0.0.1' || req.headers.host?.toLowerCase() !== new URL(origin()).host) throw new HttpError(403, 'HOST_REJECTED', 'Open this example using its localhost URL.');
    const path = req.url;
    if ((req.method === 'GET' || req.method === 'HEAD') && staticFiles.has(path)) {
      const [type, bytes] = staticFiles.get(path);
      res.writeHead(200, { 'Content-Type': type, 'Content-Length': bytes.length });
      res.end(req.method === 'HEAD' ? undefined : bytes);
      return;
    }
    if (req.method === 'GET' && path === '/api/session') {
      send(res, 200, view(findSession(req) ?? newSession(res)));
      return;
    }
    if (req.method !== 'POST' || !['/api/register/options', '/api/register/verify', '/api/login/options', '/api/login/verify', '/api/logout', '/api/authorize'].includes(path)) throw new HttpError(404, 'NOT_FOUND', 'No such local endpoint.');
    if (req.headers.origin !== origin() || req.headers['sec-fetch-site'] === 'cross-site') throw new HttpError(403, 'ORIGIN_REJECTED', 'A same-origin request is required.');
    const session = findSession(req);
    if (!session) throw new HttpError(401, 'SESSION_REQUIRED', 'Refresh this page to begin a local session.');
    const csrf = req.headers['x-csrf-token'];
    if (typeof csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(csrf) || !timingSafeEqual(Buffer.from(csrf), Buffer.from(session.csrf))) throw new HttpError(403, 'CSRF_REJECTED', 'Refresh this page before retrying.');
    const pending = path.endsWith('/verify') ? takeChallenge(session, path.includes('/register/') ? 'register' : 'login') : null;
    const body = await readJson(req);
    if (pending) assertCurrentChallenge(session, pending);
    else assertActiveSession(session);
    if (!pending) emptyBody(body);
    if (path === '/api/logout') { send(res, 200, view(rotateSession(session, res))); return; }
    if (path === '/api/authorize') {
      if (!session.userId) throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Register or log in before using the passkey vault.');
      send(res, 200, { authorized: true }); return;
    }
    if (path === '/api/register/options') {
      if (credentials.size >= 256) throw new HttpError(503, 'CREDENTIAL_LIMIT', 'Restart the local example to clear its synthetic credential inventory.');
      const userId = session.userId ?? token();
      const owned = [...credentials.values()].filter((credential) => credential.userId === userId);
      if (owned.length >= 8) throw new HttpError(409, 'CREDENTIAL_LIMIT', 'This synthetic identity already has eight credentials.');
      const revision = ++session.challengeRevision;
      session.pending = null;
      const options = await generateRegistrationOptions({ rpName: 'Verified local notes', rpID: 'localhost', userName: `synthetic-${userId.slice(0, 8)}`, userID: Buffer.from(userId, 'base64url'),
        attestationType: 'none', supportedAlgorithmIDs: [-7, -257], timeout: challengeTtlMs,
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: owned.map((credential) => ({ id: credential.id, transports: credential.transports })), extensions: { prf: {} },
      });
      assertActiveSession(session);
      if (revision !== session.challengeRevision) throw new HttpError(409, 'CHALLENGE_UNAVAILABLE', 'A newer options request replaced this challenge.');
      session.pending = { kind: 'register', challenge: options.challenge, userId, expires: now() + challengeTtlMs, revision };
      send(res, 200, options); return;
    }
    if (path === '/api/login/options') {
      if (credentials.size === 0) throw new HttpError(404, 'NO_CREDENTIALS', 'Register a passkey before logging in; this server stores credentials only in memory.');
      const revision = ++session.challengeRevision;
      session.pending = null;
      const options = await generateAuthenticationOptions({ rpID: 'localhost', userVerification: 'required', timeout: challengeTtlMs });
      assertActiveSession(session);
      if (revision !== session.challengeRevision) throw new HttpError(409, 'CHALLENGE_UNAVAILABLE', 'A newer options request replaced this challenge.');
      session.pending = { kind: 'login', challenge: options.challenge, expires: now() + challengeTtlMs, revision };
      send(res, 200, options); return;
    }
    const kind = path.includes('/register/') ? 'register' : 'login';
    ceremonyBody(body, kind);
    try {
      if (kind === 'register') {
        const result = await verifyRegistrationResponse({ response: body, expectedChallenge: pending.challenge, expectedOrigin: origin(), expectedRPID: 'localhost', requireUserVerification: true, requireUserPresence: true, supportedAlgorithmIDs: [-7, -257] });
        assertCurrentChallenge(session, pending);
        if (!result.verified || !result.registrationInfo.userVerified) throw new Error();
        const credential = result.registrationInfo.credential;
        if (credentials.has(credential.id)) throw new Error();
        // Other sessions can finish registration after this session obtained its options.
        if (credentials.size >= 256 || [...credentials.values()].filter((entry) => entry.userId === pending.userId).length >= 8) throw new HttpError(409, 'CREDENTIAL_LIMIT', 'The synthetic credential limit was reached.');
        credentials.set(credential.id, { ...credential, userId: pending.userId });
        send(res, 200, { verified: true, ...view(rotateSession(session, res, pending.userId, credential.id)) });
      } else {
        const credential = credentials.get(body.id);
        if (!credential) throw new Error();
        const result = await verifyAuthenticationResponse({ response: body, credential, expectedChallenge: pending.challenge, expectedOrigin: origin(), expectedRPID: 'localhost', requireUserVerification: true });
        assertCurrentChallenge(session, pending);
        if (!result.verified || !result.authenticationInfo.userVerified) throw new Error();
        credential.counter = Math.max(credential.counter, result.authenticationInfo.newCounter);
        send(res, 200, { verified: true, ...view(rotateSession(session, res, credential.userId, credential.id)) });
      }
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(400, 'VERIFICATION_FAILED', 'WebAuthn verification failed. Start a new ceremony.');
    }
  }
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const archiveIndex = process.argv.indexOf('--archive');
  const archive = archiveIndex === -1 ? process.env.VAULT_ARCHIVE : process.argv[archiveIndex + 1];
  if (archiveIndex !== -1 && !archive) throw new Error('--archive requires a local npm archive path.');
  const port = Number(process.env.PORT ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT must be 0 through 65535.');
  const server = createNotesServer({ archive });
  server.listen(port, '127.0.0.1', () => console.log(JSON.stringify({ origin: new URL(`http://localhost:${server.address().port}`).origin, port: server.address().port })));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
}
