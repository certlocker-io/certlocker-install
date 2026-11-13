"""Run the rendered installer ingress against a synthetic local backend."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(args[0] + ' failed: ' + result.stderr)
    return result.stdout


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"success":true}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@unittest.skipUnless(shutil.which('docker') and shutil.which('openssl'), 'Docker/OpenSSL required')
class IngressRateTests(unittest.TestCase):
    def exercise(self, limit):
        image = re.search(r'image: (\S+)', (ROOT / 'uncloud/ingress/compose.yaml.j2').read_text())[1]
        backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        name = 'installer-rate-test-' + uuid.uuid4().hex[:10]
        started = False
        try:
            with tempfile.TemporaryDirectory(prefix='installer-http-rate-') as temp:
                directory = Path(temp)
                run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-keyout', str(directory / 'key'), '-out', str(directory / 'cert'))
                (directory / 'ingress.pem').write_bytes((directory / 'key').read_bytes() + (directory / 'cert').read_bytes())
                values = dict(inventory_hostname='fixture', groups={'uncloud': ['fixture']},
                              hostvars={'fixture': {'uncloud_mesh_ip': '127.0.0.1'}},
                              uncloud_vpn_cidrs=['127.0.0.1/32'], uncloud_api_single_owner=False,
                              uncloud_ingress_settings={'hostname': 'localhost',
                                'backoffice_hostname': 'backoffice.test', 'grafana_hostname': 'grafana.test'})
                if limit is not None:
                    values['uncloud_http_rate_limit'] = limit
                env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
                env.filters['bool'] = bool
                config = env.from_string((ROOT / 'uncloud/ingress/haproxy.cfg.j2').read_text()).render(**values)
                tls_port = port()
                config = config.replace('bind :443', f'bind 127.0.0.1:{tls_port}')
                config = config.replace('bind :80', f'bind 127.0.0.1:{port()}')
                config = config.replace('bind 127.0.0.1:8404', f'bind 127.0.0.1:{port()}')
                config = config.replace('/run/secrets/ingress.pem', '/fixture/ingress.pem')
                config = config.replace('/run/haproxy/admin.sock', '/tmp/admin.sock')
                config = re.sub(r'127\.0\.0\.1:(3080|3081|8300|3001|9090)\b', f'127.0.0.1:{backend.server_port}', config)
                (directory / 'haproxy.cfg').write_text(config)
                run('docker', 'run', '--rm', '--user', '0:0', '-v', f'{temp}:/fixture:ro', image,
                    'haproxy', '-c', '-f', '/fixture/haproxy.cfg')
                run('docker', 'run', '-d', '--name', name, '--network', 'host', '--user', '0:0',
                    '-v', f'{temp}:/fixture:ro', image, 'haproxy', '-db', '-f', '/fixture/haproxy.cfg')
                started = True
                context = ssl.create_default_context(cafile=str(directory / 'cert'))

                def request(host, path='/', spoof='198.51.100.1'):
                    conn = http.client.HTTPSConnection('localhost', tls_port, context=context, timeout=3)
                    try:
                        conn.request('GET', path, headers={'Host': host, 'CF-Connecting-IP': spoof})
                        response = conn.getresponse()
                        response.read()
                        return response.status
                    finally:
                        conn.close()

                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    try:
                        if request('localhost', '/health/ready') == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                else:
                    self.fail('Synthetic ingress did not become ready')
                for index in range(60 if limit is None else limit):
                    self.assertEqual(request(('localhost', 'backoffice.test')[index % 2],
                                             spoof=f'198.51.100.{index + 1}'), 200)
                if limit is not None:
                    self.assertEqual(request('localhost', spoof='203.0.113.1'), 429)
                    self.assertEqual(request('backoffice.test', spoof='203.0.113.2'), 429)
                    self.assertEqual(request('localhost', '/health/ready'), 200)
        finally:
            if started:
                run('docker', 'rm', '-f', name)
            backend.shutdown()
            backend.server_close()

    def test_default_allows_browser_burst(self):
        self.exercise(None)

    def test_custom_budget_covers_both_frontends_and_rejects_spoofed_client_headers(self):
        self.exercise(4)
