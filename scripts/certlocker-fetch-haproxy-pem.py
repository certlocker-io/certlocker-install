#!/usr/bin/env python3
"""Download a Trust certificate and private key to ~/certlocker-haproxy.pem."""

import argparse
from functools import partial
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


PEM_BLOCK = re.compile(rb'-----BEGIN ([A-Z0-9 ]+)-----\s+.*?-----END \1-----', re.S)


class FetchError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A redirect must not forward the Trust credential to another endpoint.
        return None


def request(base, path, token, *, plain=False):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from certlocker_gateway import GatewayRoutes
    path = GatewayRoutes().path(path)
    media = 'text/plain' if plain else 'application/json'
    req = urllib.request.Request(base.rstrip('/') + '/' + path, headers={
        'x-api-token': token,
        'Accept': media,
        'Content-Type': media,
        'User-Agent': 'CertLocker-Ansible-Uploader/1.0',
    })
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
            data = response.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        # URLs can contain certificate tokens; response bodies can contain secrets.
        raise FetchError(f'Trust request failed (HTTP {exc.code}).') from None
    except (OSError, urllib.error.URLError):
        raise FetchError('Trust connection or TLS verification failed.') from None
    if not data or len(data) > 4 * 1024 * 1024:
        raise FetchError('Trust returned an empty or oversized response.')
    return data


def resolve_certificate_token(base, api_token, name):
    try:
        metadata = json.loads(request(base, 'api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''), api_token))
        secret_id = metadata['id']
        if not isinstance(secret_id, str) or not secret_id:
            raise ValueError()
        raw = request(base, 'api/v1/secret/fetch/' + urllib.parse.quote(secret_id, safe=''), api_token, plain=True).decode()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = raw
        value = payload.get('value') if isinstance(payload, dict) else payload
        if not isinstance(value, str) or not value.strip() or any(c.isspace() for c in value.strip()):
            raise ValueError()
        return value.strip()
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise FetchError('The named Trust secret did not contain a certificate token.') from None


def find_openssl():
    # macOS shells may find Apple's LibreSSL before Homebrew OpenSSL.
    candidates = [shutil.which('openssl'),
                  '/opt/homebrew/opt/openssl@3/bin/openssl',
                  '/usr/local/opt/openssl@3/bin/openssl']
    for binary in dict.fromkeys(candidates):
        if not binary:
            continue
        try:
            result = subprocess.run([binary, 'version'], capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            continue
        version = re.match(rb'OpenSSL (\d+)\.(\d+)\.(\d+)', result.stdout)
        if result.returncode == 0 and version and tuple(map(int, version.groups())) >= (1, 1, 1):
            return binary
    raise FetchError('OpenSSL 1.1.1 or newer is required; macOS LibreSSL is unsupported. '
                     'Install Homebrew openssl@3 or put a compatible openssl on PATH.')


def openssl(args, data, *, binary, failure):
    try:
        result = subprocess.run([binary, *args], input=data, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise FetchError('OpenSSL is unavailable or timed out.') from None
    if result.returncode:
        # Never include raw OpenSSL output: it may contain private material.
        raise FetchError(f'{failure}; output was not changed.')
    return result.stdout


def split_bundle(raw):
    blocks = [(match.group(1), match.group(0).replace(b'\r\n', b'\n') + b'\n') for match in PEM_BLOCK.finditer(raw)]
    certs = [data for label, data in blocks if label == b'CERTIFICATE']
    keys = [data for label, data in blocks if label in (b'PRIVATE KEY', b'RSA PRIVATE KEY', b'EC PRIVATE KEY')]
    if not certs or len(keys) != 1 or len(blocks) != len(certs) + len(keys):
        raise FetchError('Bundle must contain a certificate chain and exactly one unencrypted private key.')
    return certs, keys[0]


def validate_bundle(raw, hostname=None):
    run_openssl = partial(openssl, binary=find_openssl())
    certs, key = split_bundle(raw)
    for index, cert in enumerate(certs, start=1):
        run_openssl(['x509', '-noout'], cert, failure=f'Certificate {index} could not be parsed')
    run_openssl(['pkey', '-passin', 'pass:', '-check', '-noout'], key,
                failure='Private-key consistency validation failed')
    key_public = run_openssl(['pkey', '-passin', 'pass:', '-pubout', '-outform', 'DER'], key,
                            failure='Private-key public component could not be read')
    cert_public = run_openssl(['x509', '-pubkey', '-noout'], certs[0],
                             failure='Leaf certificate public key could not be read')
    cert_public = run_openssl(['pkey', '-pubin', '-outform', 'DER'], cert_public,
                             failure='Leaf certificate public key could not be decoded')
    if key_public != cert_public:
        raise FetchError('Private key does not match the leaf certificate; output was not changed.')
    run_openssl(['x509', '-checkend', '0', '-noout'], certs[0],
                failure='Leaf certificate has expired or its expiry could not be checked')
    if hostname:
        result = run_openssl(['x509', '-checkhost', hostname, '-noout'], certs[0],
                             failure='Leaf certificate hostname validation failed')
        # Some OpenSSL versions return zero even when the hostname mismatches.
        if result.strip() != f'Hostname {hostname} does match certificate'.encode():
            raise FetchError('Leaf certificate does not match the requested hostname; output was not changed.')
    # HAProxy accepts certificate chain plus key in a single PEM file.
    return b''.join(certs) + key


def write_bundle(output, data, force=False):
    output = Path(output).expanduser()
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise FetchError('Output must be a regular file, not a symlink or directory.')
    if output.exists() and not force:
        raise FetchError('Output already exists or is a symlink; use --force only for an intended replacement.')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.haproxy-pem-', dir=output.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, output)
        else:
            # Atomic no-clobber install, including a destination created during fetch.
            os.link(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return output.absolute()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-url', default='https://trust.certlocker.io/rest')
    parser.add_argument('--secret-name', required=True, help='Exact company-owned certificate token record')
    parser.add_argument('--output', default='~/certlocker-haproxy.pem', help='Destination PEM (default: ~/certlocker-haproxy.pem; replaces existing file).')
    parser.add_argument('--validate', action='store_true', help='Also check certificate/key consistency and expiry with OpenSSL.')
    parser.add_argument('--hostname', help='Also validate the certificate and check this hostname.')
    parser.add_argument('--force', action='store_true', help=argparse.SUPPRESS)  # Older commands remain valid.
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.api_url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        parser.error('--api-url must be an HTTPS URL without credentials, query or fragment')
    try:
        token = os.environ.get('CERTLOCKER_TOKEN') or getpass.getpass('Trust API token: ')
        if not token.strip():
            raise FetchError('A Trust API token is required.')
        certificate_token = resolve_certificate_token(args.api_url, token, args.secret_name)
        raw = request(args.api_url, 'api/v1/cert/fetch-bundle/' + urllib.parse.quote(certificate_token, safe=''), token, plain=True)
        if args.validate or args.hostname:
            pem = validate_bundle(raw, args.hostname)
        else:
            certs, key = split_bundle(raw)
            pem = b''.join(certs) + key
        path = write_bundle(args.output, pem, force=True)
        print(f'Saved PEM (mode 0600): {path}')
    except FetchError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, EOFError, KeyboardInterrupt):
        print('PEM fetch/write interrupted or failed; no credential details logged.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
