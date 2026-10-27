import { addPasskey, createPrfBinding, requestPrf, seal, openWithPrf, openWithRecovery, serializeVault, parseVault, vaultBindings } from '/vendor/vault.js';

const $ = (id) => document.getElementById(id);
const storageKey = 'verified-notes.envelope.v1';
const pendingKey = 'verified-notes.pending.v1';
const initialNote = 'Synthetic notebook\n\nThis note is local. Its plaintext and PRF output are never sent to the server.\n';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
let session = null;
let busy = false;
let candidate = null;

function fail(code, message) { throw Object.assign(new Error(message), { code }); }
function sameBytes(left, right) { return left.length === right.length && left.every((value, index) => value === right[index]); }
function stored() { return localStorage.getItem(storageKey); }
function onSavedNote() {
  try { return vaultBindings(parseVault(stored())).some((binding) => binding.credentialId === session?.credentialId); }
  catch { return false; }
}
function render() {
  const authenticated = session?.authenticated === true;
  const exists = Boolean(stored());
  $('add-passkey').disabled = busy || Boolean(candidate) || !authenticated || !exists || onSavedNote();
  $('identity').textContent = authenticated ? 'Authenticated by server-verified WebAuthn.' : 'Not authenticated.';
  $('storage-state').textContent = exists ? 'An encrypted envelope is saved in this browser.' : 'No saved envelope.';
  for (const id of ['register', 'login']) $(id).disabled = busy || !session || Boolean(candidate);
  $('logout').disabled = busy || !session;
  $('encrypt').disabled = busy || !authenticated || $('note').disabled || Boolean(candidate);
  $('note').readOnly = busy || Boolean(candidate);
  $('unlock').disabled = busy || Boolean(candidate) || !authenticated || !exists;
  $('recover').disabled = busy || Boolean(candidate) || !exists || !$('recovery-key').value;
  $('save-recovery').disabled = busy || !candidate || !$('confirm-recovery').value;
  $('pending').hidden = !candidate;
}
async function readSession() {
  const response = await fetch('/api/session', { credentials: 'same-origin' });
  const result = await response.json();
  if (!response.ok) fail(result.error?.code ?? 'HTTP_FAILED');
  return result;
}
async function api(path, body = {}) {
  const response = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) {
    if (['SESSION_REQUIRED', 'CSRF_REJECTED'].includes(result.error?.code)) {
      session = { ...session, authenticated: false, credentialId: null };
      let refreshed = false;
      try { session = await readSession(); refreshed = true; } catch { /* Keep the draft available if the server has become unreachable. */ }
      $('status').textContent = refreshed
        ? 'Session changed. Displayed unsaved content is still unsaved. Register or log in again, then retry the operation.'
        : 'Session changed, but it could not be refreshed. Displayed unsaved content is still unsaved. Reconnect, then register or log in again.';
      fail('SESSION_CHANGED');
    }
    fail(result.error?.code ?? 'HTTP_FAILED', result.error?.message ?? 'The local request failed.');
  }
  return result;
}
async function action(operation) {
  if (busy) return;
  busy = true;
  $('error').hidden = true;
  render();
  try { await operation(); }
  catch (error) {
    const code = typeof error.code === 'string' && /^[A-Z_]{1,50}$/.test(error.code) ? error.code : 'LOCAL_OPERATION_FAILED';
    const messages = {
      PRF_UNAVAILABLE: 'This credential did not return PRF output. The saved envelope was retained.',
      WEBAUTHN_FAILED: 'The credential operation failed or was dismissed. The saved envelope was retained.',
      UNLOCK_FAILED: 'The key is wrong or the encrypted envelope was changed. The saved envelope was retained.',
      INVALID_ENVELOPE: 'The saved envelope is invalid. Its stored bytes were retained.',
      RECOVERY_CONFIRMATION: 'Re-enter the exact new recovery key before saving.',
      STORAGE_CHANGED: 'Storage changed while the candidate was pending. The existing saved envelope was retained.',
      NOTE_TOO_LARGE: 'The note exceeds 64 KiB of UTF-8.',
      VERIFICATION_FAILED: 'The server rejected the WebAuthn ceremony. Start again.',
      CHALLENGE_UNAVAILABLE: 'The challenge expired, was replaced, or was already used. Start again.',
      AUTHENTICATION_REQUIRED: 'Register or log in before using the passkey vault.',
      SESSION_CHANGED: 'The session changed. Displayed unsaved content is still unsaved. Session refresh did not clear drafts, pending candidates or encrypted envelopes. Authenticate again before retrying. The failed operation was not replayed.',
      NO_CREDENTIALS: 'Register a passkey first. This server loses its synthetic credential inventory on restart.',
      PASSKEY_NOT_ADDED: 'This passkey was not added: it already opens the note, the note has eight passkeys, or the wrong passkey answered. The saved envelope was retained.',
    };
    $('error').textContent = `${code}: ${messages[code] ?? 'The operation could not complete. The saved envelope was retained; retry or use independent recovery.'}`;
    $('error').hidden = false;
  } finally { busy = false; render(); }
}

// Deliberately project only ceremony fields; PRF extension results never enter an HTTP body.
function ceremonyResponse(credential, kind) {
  const fields = kind === 'register' ? ['clientDataJSON', 'attestationObject', 'transports'] : ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle'];
  return { id: credential.id, rawId: credential.rawId, type: credential.type, response: Object.fromEntries(fields.filter((key) => credential.response[key] !== undefined).map((key) => [key, credential.response[key]])), clientExtensionResults: {} };
}

$('register').addEventListener('click', () => action(async () => {
  const optionsJSON = await api('/api/register/options');
  const credential = await globalThis.SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
  session = await api('/api/register/verify', ceremonyResponse(credential, 'register'));
  if (!session.verified || !session.authenticated) fail('VERIFICATION_FAILED');
  $('note').disabled = false;
  if (!stored() && !$('note').value) $('note').value = initialNote;
  $('status').textContent = credential.clientExtensionResults?.prf?.enabled === true
    ? 'Registration verified. PRF support was reported; encryption evaluates it locally.'
    : 'Registration verified. PRF support is unknown or unavailable; encryption will check it without replacing saved data.';
}));

$('login').addEventListener('click', () => action(async () => {
  const optionsJSON = await api('/api/login/options');
  const credential = await globalThis.SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
  session = await api('/api/login/verify', ceremonyResponse(credential, 'login'));
  if (!session.verified || !session.authenticated) fail('VERIFICATION_FAILED');
  $('note').disabled = false;
  if (!stored() && !$('note').value) $('note').value = initialNote;
  $('status').textContent = 'Login signature verified. Unlock the saved note separately.';
}));

$('encrypt').addEventListener('click', () => action(async () => {
  await api('/api/authorize');
  const bytes = encoder.encode($('note').value);
  let prf;
  let checked;
  let recovered;
  try {
    if (bytes.length > 64 * 1024) fail('NOTE_TOO_LARGE');
    const previous = stored();
    let dropped = 0;
    try { dropped = previous ? vaultBindings(parseVault(previous)).filter((item) => item.credentialId !== session.credentialId).length : 0; }
    catch { /* An unreadable saved envelope can still be replaced by a confirmed candidate. */ }
    const binding = createPrfBinding(session.credentialId, session.rpId);
    prf = await requestPrf(binding);
    const { vault, recoveryKey } = await seal(bytes, { binding, prfOutput: prf });
    const serialized = serializeVault(vault);
    localStorage.setItem(pendingKey, serialized);
    const savedCandidate = localStorage.getItem(pendingKey);
    if (savedCandidate !== serialized) fail('STORAGE_CHANGED');
    const readBack = parseVault(savedCandidate);
    checked = await openWithPrf(readBack, prf);
    recovered = await openWithRecovery(readBack, recoveryKey);
    if (!sameBytes(bytes, checked) || !sameBytes(bytes, recovered)) fail('UNLOCK_FAILED');
    candidate = { serialized, recoveryKey, previous };
    $('pending-warning').textContent = dropped ? `Saving removes ${dropped} other passkey${dropped === 1 ? '' : 's'} from this note. Add them again afterwards.` : '';
    $('pending-warning').hidden = !dropped;
    $('new-recovery-key').value = recoveryKey;
    $('confirm-recovery').value = '';
    $('status').textContent = 'Encrypted candidate checked through PRF and recovery. Save and confirm the new recovery key to commit it.';
  } finally { bytes.fill(0); prf?.fill(0); checked?.fill(0); recovered?.fill(0); }
}));

$('save-recovery').addEventListener('click', () => action(async () => {
  if (!candidate || $('confirm-recovery').value !== candidate.recoveryKey) fail('RECOVERY_CONFIRMATION');
  if (stored() !== candidate.previous || localStorage.getItem(pendingKey) !== candidate.serialized) fail('STORAGE_CHANGED');
  let checked;
  try {
    checked = await openWithRecovery(parseVault(candidate.serialized), $('confirm-recovery').value);
    // Web Storage setItem replaces one value or throws; no old envelope is deleted first.
    localStorage.setItem(storageKey, candidate.serialized);
  } finally { checked?.fill(0); }
  candidate = null;
  $('new-recovery-key').value = '';
  $('confirm-recovery').value = '';
  try { localStorage.removeItem(pendingKey); } catch { /* The committed envelope remains usable if pending cleanup fails. */ }
  $('status').textContent = 'Encrypted note saved. Reload, then unlock with the passkey or independently saved recovery key.';
}));

$('unlock').addEventListener('click', () => action(async () => {
  await api('/api/authorize');
  const vault = parseVault(stored());
  let prf;
  let bytes;
  try {
    prf = await requestPrf(vaultBindings(vault));
    bytes = await openWithPrf(vault, prf);
    $('note').value = decoder.decode(bytes);
    $('note').disabled = false;
    $('status').textContent = 'Saved note unlocked locally with passkey PRF.';
  } finally { prf?.fill(0); bytes?.fill(0); }
}));

// The recovery key is unchanged, so the candidate is committed after both passkeys open the stored copy.
$('add-passkey').addEventListener('click', () => action(async () => {
  await api('/api/authorize');
  const previous = stored();
  const vault = parseVault(previous);
  const binding = { ...vault.binding, credentialId: session.credentialId };
  let existing;
  let added;
  let before;
  let viaExisting;
  let viaAdded;
  try {
    $('status').textContent = 'Use the passkey you are logged in with, then a passkey that already opens this note.';
    added = await requestPrf(binding);
    existing = await requestPrf(vaultBindings(vault));
    const next = await addPasskey(vault, { prfOutput: existing }, { binding, prfOutput: added })
      .catch((error) => (error?.code === 'INVALID_INPUT' ? fail('PASSKEY_NOT_ADDED') : Promise.reject(error)));
    const serialized = serializeVault(next);
    localStorage.setItem(pendingKey, serialized);
    const readBack = localStorage.getItem(pendingKey);
    if (readBack !== serialized) fail('STORAGE_CHANGED');
    const candidateVault = parseVault(readBack);
    before = await openWithPrf(vault, existing);
    viaExisting = await openWithPrf(candidateVault, existing);
    viaAdded = await openWithPrf(candidateVault, added);
    if (!sameBytes(before, viaExisting) || !sameBytes(before, viaAdded)) fail('UNLOCK_FAILED');
    if (stored() !== previous) fail('STORAGE_CHANGED');
    localStorage.setItem(storageKey, serialized);
    try { localStorage.removeItem(pendingKey); } catch { /* The committed envelope remains usable if pending cleanup fails. */ }
    $('status').textContent = `Passkey added. ${vaultBindings(candidateVault).length} passkeys can unlock this note; the recovery key is unchanged.`;
  } finally { existing?.fill(0); added?.fill(0); before?.fill(0); viaExisting?.fill(0); viaAdded?.fill(0); }
}));

$('recover').addEventListener('click', () => action(async () => {
  let bytes;
  try {
    bytes = await openWithRecovery(parseVault(stored()), $('recovery-key').value);
    $('note').value = decoder.decode(bytes);
    $('note').disabled = false;
    $('recovery-key').value = '';
    $('status').textContent = 'Saved note recovered locally. Server authentication is unchanged.';
  } finally { bytes?.fill(0); }
}));

$('logout').addEventListener('click', () => action(async () => {
  // Clear owned plaintext even when the local HTTP logout fails.
  $('note').value = '';
  $('note').disabled = true;
  $('recovery-key').value = '';
  $('new-recovery-key').value = '';
  $('confirm-recovery').value = '';
  candidate = null;
  session = { ...session, authenticated: false, credentialId: null };
  session = await api('/api/logout');
  $('status').textContent = 'Logged out. Plaintext was cleared; encrypted envelopes were retained.';
}));

for (const id of ['recovery-key', 'confirm-recovery']) $(id).addEventListener('input', render);
try {
  session = await readSession();
  $('note').value = stored() ? '' : initialNote;
  $('note').disabled = !session.authenticated;
  $('status').textContent = stored() ? 'Saved envelope found. Log in if needed, then unlock; independent recovery also works while logged out.' : 'Register a PRF-capable passkey to encrypt the synthetic note.';
  render();
} catch {
  $('error').textContent = 'STARTUP_FAILED: Open the localhost URL printed by the server and refresh.';
  $('error').hidden = false;
}
