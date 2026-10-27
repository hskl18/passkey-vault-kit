"""Serve the anonymous fixture and SDK from one retained archive snapshot."""
import hashlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tarfile


def create_server(archive: Path):
    here = Path(__file__).resolve().parent
    archive_bytes = archive.read_bytes()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as package:
        member = package.getmember('package/dist/index.js')
        if not member.isfile() or member.size > 256 * 1024:
            raise ValueError('unexpected SDK entry')
        sdk = package.extractfile(member).read()
    routes = {
        '/': ('text/html; charset=utf-8', (here / 'index.html').read_bytes()),
        '/fixture.js': ('text/javascript; charset=utf-8', (here / 'fixture.js').read_bytes()),
        '/sdk.js': ('text/javascript; charset=utf-8', sdk),
    }
    identity = {
        'archiveSha256': hashlib.sha256(archive_bytes).hexdigest(),
        'servedSha256': {path: hashlib.sha256(body).hexdigest() for path, (_, body) in routes.items()},
    }
    routes['/artifact.json'] = ('application/json; charset=utf-8', json.dumps(identity).encode())

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            item = routes.get(self.path)
            if item is None:
                self.send_error(404)
                return
            content_type, body = item
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    return ThreadingHTTPServer(('127.0.0.1', 0), Handler)
