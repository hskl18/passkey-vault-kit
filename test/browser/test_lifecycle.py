"""Server lifecycle regressions that do not launch a browser."""
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from server import create_server


HERE = Path(__file__).resolve().parent
VERSION = json.loads((HERE.parents[1] / 'package.json').read_text())['version']
ARCHIVE = HERE.parents[1] / f'.artifacts/passkey-vault-kit-{VERSION}.tgz'


class LifecycleTests(unittest.TestCase):
    def test_browser_launch_failure_closes_owned_server_without_success_report(self):
        servers = []

        def start(archive):
            server = create_server(archive)
            servers.append(server)
            return server

        manager = MagicMock()
        manager.__enter__.return_value.chromium.launch.side_effect = RuntimeError('synthetic launch failure')
        with tempfile.TemporaryDirectory(prefix='vault-browser-lifecycle-') as temporary:
            output = Path(temporary) / 'result.json'
            args = ['verify_browser.py', '--archive', str(ARCHIVE), '--output', str(output)]
            with patch.object(sys, 'argv', args), patch('server.create_server', side_effect=start), \
                    patch('playwright.sync_api.sync_playwright', return_value=manager):
                with self.assertRaisesRegex(RuntimeError, 'synthetic launch failure'):
                    runpy.run_path(str(HERE / 'verify_browser.py'), run_name='__main__')
            self.assertFalse(output.exists())
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].socket.fileno(), -1)
        manager.__exit__.assert_called_once()


if __name__ == '__main__':
    unittest.main()
