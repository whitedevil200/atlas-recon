#!/usr/bin/env python3
"""Exercise the installed free binaries without scanning any target."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import http.server
import socketserver
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine_bundle
import integrations

engine_bundle.activate()
engines = engine_bundle.manifest()[engine_bundle.platform_key()]
for name in engines:
    path = shutil.which(name)
    if not path:
        raise RuntimeError('Missing managed engine: ' + name)
    process = subprocess.run([path, '--version' if name == 'findomain' else '-version'],
                             capture_output=True, timeout=20)
    if process.returncode:
        raise RuntimeError('Version check failed: ' + name)
    print(name + ': executable started successfully')
process = subprocess.run(['subfinder', '-ls', '-oJ', '-duc'], capture_output=True, timeout=20, check=True)
sources = {}
for line in process.stdout.decode('utf-8', 'replace').splitlines():
    try:
        row = json.loads(line)
        sources[row['name']] = row
    except (ValueError, KeyError, TypeError):
        pass
for name in ['crtsh', 'waybackarchive', 'rapiddns', 'digitorus', 'shodanct']:
    if sources.get(name, {}).get('keyRequirement') != 'none':
        raise RuntimeError('Subfinder source is no longer keyless: ' + name)
print('Seven real binary checks and keyless provider metadata passed; no public target was scanned.')


class HTTPFixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(403)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<title>ATLAS local fixture</title>')

    def log_message(self, *args):
        pass


class ClosedTLSFixture(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.close()


with tempfile.TemporaryDirectory() as directory:
    inputs = Path(directory) / 'input.txt'
    # Use a literal loopback address: HTTPx's DNS backend need not resolve
    # the OS-specific localhost name. DNS-input normalization is covered by
    # the active-workflow regression tests separately.
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), HTTPFixture) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            inputs.write_text(f'http://127.0.0.1:{server.server_port}\n', encoding='utf-8')
            command = integrations.build_command('httpx', shutil.which('httpx'), inputs, 'localhost', 10, 5, {})
            process = subprocess.run(command, capture_output=True, timeout=30, check=True)
            records = [json.loads(line) for line in process.stdout.decode('utf-8', 'replace').splitlines() if line]
            if not any(row.get('status_code') == 403 for row in records):
                raise RuntimeError('HTTPx did not preserve the local 403 response')
        finally:
            server.shutdown()
            thread.join(timeout=2)
    # No real TLS site is needed to catch incompatible CLI flags: the runner
    # must accept the complete adapter argument combination and exit cleanly.
    with socketserver.TCPServer(('127.0.0.1', 0), ClosedTLSFixture) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            inputs.write_text(f'127.0.0.1:{server.server_address[1]}\n', encoding='utf-8')
            command = integrations.build_command('tlsx', shutil.which('tlsx'), inputs, 'localhost', 10, 5, {})
            subprocess.run(command, capture_output=True, timeout=15, check=True)
        finally:
            server.shutdown()
            thread.join(timeout=2)
print('Actual HTTPx 403 parsing and TLSx adapter-option checks passed against loopback fixtures.')
