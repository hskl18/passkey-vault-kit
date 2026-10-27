"""Local application trial with a fresh profile and a virtual authenticator."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import tarfile
from threading import Thread
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
parser = argparse.ArgumentParser()
version = json.loads((ROOT / 'package.json').read_text())['version']
# Same lookup order as server.mjs: the source root first, then .artifacts.
archive_name = f'passkey-vault-kit-{version}.tgz'
default_archive = ROOT / archive_name if (ROOT / archive_name).exists() else ROOT / '.artifacts' / archive_name
parser.add_argument('--archive', type=Path, default=default_archive)
parser.add_argument('--output', type=Path, default=ROOT / '.artifacts/verified-notes/result.json')
args = parser.parse_args()

archive = args.archive.resolve()
if not archive.is_file():
    parser.error(f'Run "npm run build && npm pack" in the repository root first (expected {archive}).')
archive_bytes = archive.read_bytes()
with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as package:
    sdk_bytes = package.extractfile('package/dist/index.js').read()
sources = {name: (HERE / name).read_bytes() for name in
           ['server.mjs', 'app.js', 'index.html', 'style.css', 'verify_browser.py', 'package-lock.json']}
report = {'scope': 'localhost application; synthetic credentials and note; fresh Chrome profile; virtual authenticator',
          'archiveSha256': hashlib.sha256(archive_bytes).hexdigest(),
          'sdkSha256': hashlib.sha256(sdk_bytes).hexdigest(),
          'harnessSha256': {name: hashlib.sha256(value).hexdigest() for name, value in sources.items()},
          'checks': [], 'realProvidersTested': False}
server = subprocess.Popen(['node', str(HERE / 'server.mjs'), '--archive', str(archive)], cwd=HERE,
                          env={**os.environ, 'PORT': '0'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    ready = queue.Queue()
    Thread(target=lambda: ready.put(server.stdout.readline()), daemon=True).start()
    line = ready.get(timeout=20)
    if not line:
        raise RuntimeError('Local example did not start: ' + server.stderr.read()[:1000])
    origin = json.loads(line)['origin']
    base = urlsplit(origin)
    assert base.scheme == 'http' and base.hostname == 'localhost' and base.port
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
            args=['--disable-background-networking', '--disable-component-update', '--disable-sync'])
        try:
            report['browserVersion'] = browser.version
            context = browser.new_context()
            blocked = []
            api_bodies = []
            failures = []

            def restrict(route):
                parsed = urlsplit(route.request.url)
                if (parsed.scheme, parsed.hostname, parsed.port) == (base.scheme, base.hostname, base.port):
                    route.continue_()
                else:
                    blocked.append(parsed.hostname)
                    route.abort()

            context.route('**/*', restrict)
            page = context.new_page()
            page.on('pageerror', lambda error: failures.append(str(error)))
            busy_locks = []

            def observe_busy(route):
                busy_locks.append(page.locator('#note').evaluate('(element) => element.readOnly'))
                route.continue_()

            page.route(origin + '/api/authorize', observe_busy)

            def inspect(request):
                if request.method == 'POST' and '/api/' in request.url:
                    api_bodies.append(request.post_data_json)

            page.on('request', inspect)
            cdp = context.new_cdp_session(page)
            cdp.send('WebAuthn.enable', {'enableUI': False})
            authenticator = cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                'protocol': 'ctap2', 'ctap2Version': 'ctap2_1', 'transport': 'internal',
                'hasResidentKey': True, 'hasUserVerification': True, 'isUserVerified': True,
                'hasPrf': True, 'automaticPresenceSimulation': True,
            }})['authenticatorId']
            page.goto(origin, wait_until='networkidle')
            page.wait_for_function("!document.getElementById('register').disabled")
            assert context.request.get(origin + '/vendor/vault.js').body() == sdk_bytes

            def state():
                response = context.request.get(origin + '/api/session')
                assert response.status == 200
                return response.json()

            def post(path, body=None, headers=None):
                return context.request.post(origin + path, data={} if body is None else body,
                    headers={'Origin': origin, 'X-CSRF-Token': state()['csrfToken'], **(headers or {})})

            def act(button, expected):
                page.locator('#' + button).click()
                page.wait_for_function("expected => !document.getElementById('logout').disabled && "
                    "(document.getElementById('status').textContent.includes(expected) || !document.getElementById('error').hidden)", arg=expected)
                assert page.locator('#error').is_hidden(), page.locator('#error').inner_text()
                assert expected in page.locator('#status').inner_text()

            def negative(button, code):
                page.locator('#' + button).click()
                page.wait_for_function("code => !document.getElementById('logout').disabled && "
                    "!document.getElementById('error').hidden && document.getElementById('error').textContent.includes(code)", arg=code)

            def saved():
                return page.evaluate("localStorage.getItem('verified-notes.envelope.v1')")

            def passed(case, **details):
                report['checks'].append({'case': case, 'passed': True, **details})

            assert state()['authenticated'] is False
            assert post('/api/authorize').status == 401
            assert post('/api/logout', headers={'Origin': 'https://example.invalid'}).status == 403
            assert post('/api/logout', headers={'X-CSRF-Token': 'invalid'}).status == 403
            assert state()['authenticated'] is False
            passed('unauthenticated operation, foreign Origin and invalid CSRF are rejected')

            act('register', 'Registration verified')
            assert state()['authenticated'] is True and state()['credentialId']
            passed('native credential registration is accepted by server verification')

            note = 'Synthetic verified application note\n\u4e2d\u6587 \U0001f510\n'
            page.locator('#note').fill(note)
            act('encrypt', 'Encrypted candidate checked')
            assert saved() is None
            assert page.locator('#note').evaluate('(element) => element.readOnly')
            recovery_key = page.locator('#new-recovery-key').input_value()
            assert recovery_key
            page.locator('#confirm-recovery').fill('not-the-key')
            negative('save-recovery', 'RECOVERY_CONFIRMATION')
            assert saved() is None
            page.locator('#confirm-recovery').fill(recovery_key)
            act('save-recovery', 'Encrypted note saved')
            envelope = saved()
            assert envelope and note not in envelope and recovery_key not in envelope
            assert json.loads(envelope)['version'] == 1
            passed('checked pending candidate is committed only after independent recovery confirmation')

            page.reload(wait_until='networkidle')
            page.wait_for_function("!document.getElementById('register').disabled")
            assert page.locator('#note').input_value() == ''
            act('unlock', 'Saved note unlocked locally')
            assert page.locator('#note').input_value() == note
            assert saved() == envelope
            passed('reload obtains native PRF and unlocks persisted encrypted application data')

            act('logout', 'Logged out')
            assert state()['authenticated'] is False
            assert page.locator('#note').input_value() == '' and saved() == envelope
            assert post('/api/authorize').status == 401
            act('login', 'Login signature verified')
            assert state()['authenticated'] is True
            act('unlock', 'Saved note unlocked locally')
            assert page.locator('#note').input_value() == note
            passed('logout revokes the session while a fresh signed login restores authorized access')

            act('logout', 'Logged out')
            options_response = post('/api/login/options')
            assert options_response.status == 200
            options = options_response.json()
            assertion = page.evaluate("async optionsJSON => { const c = await SimpleWebAuthnBrowser.startAuthentication({optionsJSON}); "
                "return {id:c.id,rawId:c.rawId,type:c.type,response:c.response,clientExtensionResults:{}}; }", options)
            tampered = json.loads(json.dumps(assertion))
            signature = bytearray(base64.urlsafe_b64decode(tampered['response']['signature'] + '==='))
            signature[-1] ^= 1
            tampered['response']['signature'] = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            assert post('/api/login/verify', tampered).status == 400
            assert state()['authenticated'] is False
            assert post('/api/login/verify', assertion).status == 409
            assert state()['authenticated'] is False
            passed('changed native signature fails verification and consumes its single-use challenge')

            options = post('/api/login/options').json()
            assertion = page.evaluate("async optionsJSON => { const c = await SimpleWebAuthnBrowser.startAuthentication({optionsJSON}); "
                "return {id:c.id,rawId:c.rawId,type:c.type,response:c.response,clientExtensionResults:{}}; }", options)
            verified = post('/api/login/verify', assertion)
            assert verified.status == 200 and verified.json()['verified'] is True
            assert post('/api/login/verify', assertion).status == 409
            assert state()['authenticated'] is True
            passed('a fresh valid native assertion verifies and its replay is rejected')

            page.reload(wait_until='networkidle')
            page.wait_for_function("!document.getElementById('register').disabled")
            act('logout', 'Logged out')
            page.locator('#recovery-key').fill('A' * 43)
            negative('recover', 'UNLOCK_FAILED')
            assert saved() == envelope and state()['authenticated'] is False
            page.locator('#recovery-key').fill(recovery_key)
            act('recover', 'Saved note recovered locally')
            assert page.locator('#note').input_value() == note and saved() == envelope
            assert state()['authenticated'] is False
            passed('independent local recovery preserves ciphertext and does not authenticate an account')

            act('login', 'Login signature verified')
            draft = 'Synthetic draft retained across a missing session'
            page.locator('#note').fill(draft)
            context.clear_cookies()
            negative('encrypt', 'SESSION_CHANGED')
            assert state()['authenticated'] is False
            assert page.locator('#note').input_value() == draft and saved() == envelope
            act('login', 'Login signature verified')
            assert page.locator('#note').input_value() == draft and state()['authenticated'] is True
            passed('lost session refreshes its CSRF state and permits signed login without discarding an unsaved draft')

            page.locator('#note').fill('Synthetic uncommitted revision')
            act('encrypt', 'Encrypted candidate checked')
            assert saved() == envelope
            page.locator('#recovery-key').fill(recovery_key)
            assert page.locator('#note').evaluate('(element) => element.readOnly')
            assert page.locator('#unlock').is_disabled() and page.locator('#recover').is_disabled()
            assert page.locator('#encrypt').is_disabled()
            assert page.locator('#register').is_disabled() and page.locator('#login').is_disabled()
            assert all(busy_locks) and len(busy_locks) >= 4
            pending = page.evaluate("localStorage.getItem('verified-notes.pending.v1')")
            assert pending and pending != envelope and 'Synthetic uncommitted revision' not in pending
            passed('in-flight operations and pending confirmation lock edits and conflicting unlock actions')
            act('logout', 'Logged out')
            for identifier in ['note', 'recovery-key', 'new-recovery-key', 'confirm-recovery']:
                assert page.locator('#' + identifier).input_value() == ''
            page.reload(wait_until='networkidle')
            page.wait_for_function("!document.getElementById('register').disabled")
            assert saved() == envelope
            assert page.evaluate("localStorage.getItem('verified-notes.pending.v1')") == pending
            act('login', 'Login signature verified')
            act('unlock', 'Saved note unlocked locally')
            assert page.locator('#note').input_value() == note and saved() == envelope
            passed('logout and reload retain the old committed note without promoting an abandoned candidate')

            def presence(authenticator_id, enabled):
                cdp.send('WebAuthn.setAutomaticPresenceSimulation',
                         {'authenticatorId': authenticator_id, 'enabled': enabled})

            # A security key registers while the first device stays silent, then both open the note.
            # Chrome allows one internal virtual authenticator, so the second one uses USB transport.
            second = cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                'protocol': 'ctap2', 'ctap2Version': 'ctap2_1', 'transport': 'usb',
                'hasResidentKey': True, 'hasUserVerification': True, 'isUserVerified': True,
                'hasPrf': True, 'automaticPresenceSimulation': True,
            }})['authenticatorId']
            presence(authenticator, False)
            act('register', 'Registration verified')
            presence(authenticator, True)
            assert not page.locator('#add-passkey').is_disabled()

            # A virtual USB key without the requested credential makes Chrome reject the request,
            # so silence it after it answers the new-passkey request and before the enrolled one.
            def silence_second(event):
                if event.get('authenticatorId') == second:
                    presence(second, False)

            cdp.on('WebAuthn.credentialAsserted', silence_second)
            act('add-passkey', 'Passkey added. 2 passkeys')
            cdp.remove_listener('WebAuthn.credentialAsserted', silence_second)
            presence(second, True)
            upgraded = saved()
            assert upgraded != envelope and json.loads(upgraded)['version'] == 2
            assert note not in upgraded and recovery_key not in upgraded
            assert page.locator('#add-passkey').is_disabled()
            for silent in (second, authenticator):
                presence(silent, False)
                page.reload(wait_until='networkidle')
                page.wait_for_function("!document.getElementById('register').disabled")
                act('unlock', 'Saved note unlocked locally')
                assert page.locator('#note').input_value() == note
                presence(silent, True)
            act('logout', 'Logged out')
            page.locator('#recovery-key').fill(recovery_key)
            act('recover', 'Saved note recovered locally')
            assert page.locator('#note').input_value() == note and saved() == upgraded
            passed('a second registered passkey joins the saved note and each device unlocks it alone')

            assert set(page.evaluate('Object.keys(localStorage)')) == {'verified-notes.envelope.v1'}
            def string_values(value):
                if isinstance(value, str):
                    yield value
                elif isinstance(value, dict):
                    for nested in value.values():
                        yield from string_values(nested)
                elif isinstance(value, list):
                    for nested in value:
                        yield from string_values(nested)

            for body in api_bodies:
                assert not any(key in json.dumps(body) for key in ['prfOutput', 'recoveryKey', 'plaintext'])
                assert all(recovery_key not in value and note not in value for value in string_values(body))
                assert body.get('clientExtensionResults', {}) == {}
            assert not blocked and not failures
            report.update(externalPageRequests=len(blocked), pageErrors=len(failures),
                          inspectedApiPosts=len(api_bodies), inspectedPagePostsExcludeKnownSecrets=True,
                          postBodyCheckScope='Page API POST bodies: extension outputs, known secret fields, note and recovery string values',
                          serverSignatureVerification=True, persistedOnlyEncryptedEnvelopes=True,
                          busyStateChecks=len(busy_locks))
            act('logout', 'Logged out')
            page.screenshot(path=str(args.output.with_suffix('.png')), full_page=True)
            for authenticator_id in (authenticator, second):
                cdp.send('WebAuthn.removeVirtualAuthenticator', {'authenticatorId': authenticator_id})
            context.close()
        finally:
            browser.close()
finally:
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)

assert server.returncode == 0
assert all((HERE / name).read_bytes() == value for name, value in sources.items()), 'Harness changed during trial'
report['serverStopped'] = True
report['verifiedAt'] = datetime.now(timezone.utc).isoformat()
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
