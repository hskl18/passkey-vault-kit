"""Native browser regression with a fresh headless profile; never uses a persistent user profile."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import tarfile
from threading import Thread
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from server import create_server

here = Path(__file__).resolve().parent
project = here.parents[1]
parser = argparse.ArgumentParser()
version = json.loads((project / 'package.json').read_text())['version']
parser.add_argument('--archive', type=Path, default=project / f'.artifacts/passkey-vault-kit-{version}.tgz')
parser.add_argument('--output', type=Path, default=project / '.artifacts/browser/result.json')
args = parser.parse_args()
archive = args.archive.resolve()
archive_bytes = archive.read_bytes()
with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as package:
    expected_sdk = package.extractfile('package/dist/index.js').read()
report = {
    'verifiedAt': datetime.now(timezone.utc).isoformat(),
    'scope': 'headless Chrome; localhost only; new temporary profile; virtual authenticator; synthetic data',
    'archiveSha256': hashlib.sha256(archive_bytes).hexdigest(),
    'sdkSha256': hashlib.sha256(expected_sdk).hexdigest(),
    'playwrightVersion': importlib.metadata.version('playwright'),
    'checks': [],
    'realProvidersTested': False,
    'harnessSha256': {name: hashlib.sha256((here / name).read_bytes()).hexdigest()
        for name in ['fixture.js', 'verify_browser.py', 'server.py']},
}
server = create_server(archive)
base_url = f'http://localhost:{server.server_port}'
base = urlsplit(base_url)
server_thread = Thread(target=server.serve_forever, daemon=True)
server_thread.start()
try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
            args=['--disable-background-networking', '--disable-component-update', '--disable-sync'])
        try:
            report['browserVersion'] = browser.version
            context = browser.new_context()
            blocked = []

            def restrict(route):
                parsed = urlsplit(route.request.url)
                if parsed.scheme == base.scheme and parsed.hostname == base.hostname and parsed.port == base.port:
                    route.continue_()
                else:
                    blocked.append(parsed.hostname)
                    route.abort()

            context.route('**/*', restrict)
            page = context.new_page()
            session = context.new_cdp_session(page)
            session.send('WebAuthn.enable', {'enableUI': False})

            def authenticator(prf):
                return session.send('WebAuthn.addVirtualAuthenticator', {'options': {
                    'protocol': 'ctap2', 'ctap2Version': 'ctap2_1', 'transport': 'internal',
                    'hasResidentKey': True, 'hasUserVerification': True, 'isUserVerified': True,
                    'hasPrf': prf, 'automaticPresenceSimulation': True,
                }})['authenticatorId']

            active = authenticator(True)
            page.goto(base_url, wait_until='networkidle')
            page.wait_for_function('!!window.trial')
            identity_response = page.request.get(f'{base_url}/artifact.json')
            assert identity_response.ok, 'Fixture artifact identity unavailable'
            identity = identity_response.json()
            assert identity['archiveSha256'] == report['archiveSha256'], 'Server archive differs from runner archive'
            expected_routes = {'/': (here / 'index.html').read_bytes(),
                '/fixture.js': (here / 'fixture.js').read_bytes(), '/sdk.js': expected_sdk}
            for path, expected in expected_routes.items():
                expected_hash = hashlib.sha256(expected).hexdigest()
                assert identity['servedSha256'][path] == expected_hash, f'Server snapshot differs for {path}'
                response = page.request.get(f'{base_url}{path}')
                assert response.ok and hashlib.sha256(response.body()).hexdigest() == expected_hash
            report['servedArtifactVerified'] = True
            created = page.evaluate('() => trial.create()')
            recovery_key = created.pop('recoveryKey')
            report['checks'].append({'case': 'native PRF registration and sealing', 'passed': True, **created})
            page.reload(wait_until='networkidle')
            page.wait_for_function('!!window.trial')
            report['checks'].append({'case': 'native PRF unlock after reload', 'passed': True,
                **page.evaluate('() => trial.reopen()')})
            assert page.evaluate('() => trial.rememberPrfForRejection()')['bytes'] == 32
            session.send('WebAuthn.clearCredentials', {'authenticatorId': active})
            assert session.send('WebAuthn.getCredentials', {'authenticatorId': active})['credentials'] == []
            rotated = page.evaluate('(key) => trial.recoverAndRotate(key)', recovery_key)
            new_recovery_key = rotated.pop('recoveryKey')
            assert new_recovery_key != recovery_key
            report['checks'].append({'case': 'lost virtual credential, recovery and rotation', 'passed': True,
                'oldVirtualCredentialsRemoved': True, **rotated})
            report['checks'].append({'case': 'failed pending verification preserves old recoverable envelope', 'passed': True,
                **page.evaluate('(key) => trial.rejectPending(key)', recovery_key)})
            committed = page.evaluate('(key) => trial.commitRotation(key)', new_recovery_key)
            report['checks'].append({'case': 'verify stored replacement and independent recovery before commit',
                'passed': True, **committed})
            page.reload(wait_until='networkidle')
            page.wait_for_function('!!window.trial')
            reopened = page.evaluate('() => trial.reopen()')
            assert reopened['envelopeId'] == committed['envelopeId']
            report['checks'].append({'case': 'rotated binding unlock and recovery after reload', 'passed': True,
                **reopened, **page.evaluate('(key) => trial.recoveryOnly(key)', new_recovery_key)})
            session.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId': active, 'enabled': False})
            report['checks'].append({'case': 'native pending request cancellation', 'passed': True,
                **page.evaluate('() => trial.cancel()')})
            session.send('WebAuthn.removeVirtualAuthenticator', {'authenticatorId': active})
            active = authenticator(False)
            report['checks'].append({'case': 'credential without PRF fails closed', 'passed': True,
                **page.evaluate('(key) => trial.unsupported(key)', new_recovery_key)})
            session.send('WebAuthn.removeVirtualAuthenticator', {'authenticatorId': active})
            assert not blocked, 'Fixture attempted an external page request'
            assert page.evaluate('() => Object.keys(localStorage)') == ['synthetic-prf-envelope']
            report['persistedOnlyEncryptedEnvelope'] = True
            report['externalPageRequests'] = len(blocked)
            context.close()
        finally:
            browser.close()

finally:
    server.shutdown()
    server.server_close()
    server_thread.join(timeout=5)
    assert not server_thread.is_alive(), 'Fixture server did not stop'

report['fixtureServerStopped'] = True
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
