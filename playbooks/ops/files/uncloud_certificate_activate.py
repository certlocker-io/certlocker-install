#!/usr/bin/env python3
"""Activate a Trust-issued certificate on one preconfigured HAProxy origin.

Called by the existing Trust certificate automation after its SFTP install step.
Only a bounded tmpfs inbox is read; hostnames and paths come from root-owned setup
configuration. No API credentials, private keys or subprocess output are logged.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

BUNDLE_HELPER = Path(__file__).with_name('uncloud_certificate_bundle.py')

def command(argv, data=None):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Certificate operation failed; diagnostic suppressed')
    return result.stdout


def regular_bytes(path, limit=131072):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_size > limit:
            raise ValueError('Certificate input must be a bounded regular file')
        return stream.read(limit + 1)


def atomic_write(path, value, mode=0o400):
    if path.is_symlink():
        raise ValueError('Refusing a symlink certificate destination')
    fd, temporary = tempfile.mkstemp(prefix='.certificate-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate(raw, hostnames, workdir, cafile=None):
    # Reuse the setup validator for key correspondence and hostname matching.
    spec = importlib.util.spec_from_file_location('certificate_bundle', BUNDLE_HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    for hostname in hostnames:
        raw = helper.validate_bundle(raw, hostname)
    certs, _ = helper.split_bundle(raw)
    leaf, chain = workdir / 'leaf.pem', workdir / 'chain.pem'
    atomic_write(leaf, certs[0])
    atomic_write(chain, b''.join(certs[1:]))
    for hostname in hostnames:
        argv = ['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', hostname]
        if cafile:
            argv += ['-CAfile', str(cafile)]
        if len(certs) > 1:
            argv += ['-untrusted', str(chain)]
        command([*argv, str(leaf)])
    command(['openssl', 'x509', '-checkend', '3600', '-noout'], certs[0])
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certs[0].decode())).hexdigest()
    return raw, fingerprint


def admin(path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)


def hot_replace(path, bundle):
    certificate = b'/run/secrets/ingress.pem'
    response = admin(path, b'set ssl cert ' + certificate + b' <<\n' + bundle.strip() + b'\n\n')
    if b'Transaction created' not in response and b'Transaction updated' not in response:
        raise RuntimeError('HAProxy rejected the certificate transaction')
    response = admin(path, b'commit ssl cert ' + certificate + b'\n')
    if b'Success' not in response:
        admin(path, b'abort ssl cert ' + certificate + b'\n')
        raise RuntimeError('HAProxy certificate transaction did not commit')


def verify_origin(hostnames, fingerprint, port=443, cafile=None):
    context = ssl.create_default_context(cafile=cafile)
    for hostname in hostnames:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as plain:
            with context.wrap_socket(plain, server_hostname=hostname) as connection:
                if hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest() != fingerprint:
                    raise RuntimeError('Origin serves an unexpected certificate')
                connection.sendall(('GET /health/ready HTTP/1.1\r\nHost: ' + hostname + '\r\nConnection: close\r\n\r\n').encode())
                if not connection.recv(4096).split(b'\r\n', 1)[0].startswith(b'HTTP/1.1 200'):
                    raise RuntimeError('Origin did not pass readiness after certificate activation')


def activate(company):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', company):
        raise ValueError('Invalid company')
    runtime = Path('/run/certlocker') / company
    inbox = Path('/run/certlocker-certificate-inbox') / company / 'incoming.pem'
    config = json.loads((Path('/etc/certlocker') / company / 'certificate.json').read_text())
    hostnames = config['hostnames']
    if len(hostnames) != 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name) for name in hostnames):
        raise ValueError('Two configured UI hostnames are required')
    for directory in (runtime, inbox.parent):
        if command(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(directory)]).strip() != b'tmpfs':
            raise ValueError('Certificate plaintext must remain on tmpfs')
    destination = runtime / 'ingress' / 'ingress.pem'
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    with (runtime / 'certificate.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result_path = runtime / 'certificate-result.json'
        started = time.monotonic()
        raw = regular_bytes(inbox)
        # A timed-out SSH caller may retry after the original command completed.
        # The root-only receipt is written only after TLS checks and sealing.
        # Reverify live TLS/readiness before acknowledging an identical delivery.
        if result_path.exists() and destination.exists() and raw == regular_bytes(destination):
            receipt = json.loads(regular_bytes(result_path))
            if (receipt.get('success') is True and receipt.get('company') == company and
                    receipt.get('hostnames') == hostnames):
                try:
                    verify_origin(hostnames, receipt['fingerprint_sha256'])
                except Exception:
                    result_path.unlink(missing_ok=True)
                    inbox.unlink(missing_ok=True)
                    raise
                receipt.update(verified_at=time.time(), seconds=round(time.monotonic() - started, 3),
                               unchanged_certificate=True)
                atomic_write(result_path, json.dumps(receipt).encode(), 0o600)
                inbox.unlink(missing_ok=True)
                print('Certificate already active; both UI names verified; encrypted boot cache preserved')
                return
        # A failed attempt must never leave a stale successful activation report.
        result_path.unlink(missing_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix='validate-', dir=runtime) as temporary:
                bundle, fingerprint = validate(raw, hostnames, Path(temporary))
        except Exception:
            inbox.unlink(missing_ok=True)
            raise
        previous = regular_bytes(destination) if destination.exists() else None
        socket_path = runtime / 'haproxy/admin.sock'
        running = command(['docker', 'inspect', '--format', '{{.State.Running}}',
                           'certlocker-haproxy']).strip() == b'true'
        if running and not socket_path.exists():
            inbox.unlink(missing_ok=True)
            raise RuntimeError('Running HAProxy has no runtime socket; refusing disruptive recovery')
        started_here = False
        try:
            atomic_write(destination, bundle)
            # Save the candidate before activating; rollback re-seals the previous file.
            command(['/usr/local/sbin/certlocker-uncloud-runtime', 'seal', '--company', company])
            if running:
                hot_replace(socket_path, bundle)
            else:
                # Setup already creates the pinned container. Avoid Compose
                # discovery/container creation inside Trust's 10-second host budget.
                command(['docker', 'start', 'certlocker-haproxy'])
                started_here = True
            deadline = time.monotonic() + 5
            while True:
                try:
                    verify_origin(hostnames, fingerprint)
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)
        except Exception:
            if previous is not None:
                atomic_write(destination, previous)
                command(['/usr/local/sbin/certlocker-uncloud-runtime', 'seal', '--company', company])
                if running:
                    hot_replace(socket_path, previous)
            else:
                destination.unlink(missing_ok=True)
                command(['/usr/local/sbin/certlocker-uncloud-runtime', 'seal', '--company', company])
                # Only stop a failed first bootstrap that this invocation started.
                # Never stop an already-running proxy, even if its PEM file was lost.
                if started_here:
                    command(['docker', 'stop', 'certlocker-haproxy'])
            raise
        finally:
            inbox.unlink(missing_ok=True)
        record = {'schema_version': 1, 'company': company, 'fingerprint_sha256': fingerprint,
                  'hostnames': hostnames, 'success': True, 'activated_at': time.time(),
                  'seconds': round(time.monotonic() - started, 3)}
        atomic_write(runtime / 'certificate-result.json', json.dumps(record).encode(), 0o600)
        print('Certificate activated; both UI names verified; encrypted boot cache updated; no HAProxy restart or reload')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--company', required=True)
    args = parser.parse_args()
    try:
        activate(args.company)
    except Exception:
        print('Certificate activation failed; inspect sanitized deployment status', file=sys.stderr)
        sys.exit(1)
