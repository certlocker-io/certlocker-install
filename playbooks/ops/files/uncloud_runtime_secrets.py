#!/usr/bin/env python3
"""Keep Trust-sourced runtime files available after boot using host-encrypted storage.

The deployment API token is never part of this bundle. Secret plaintext stays in
tmpfs and subprocess stdin/stdout; systemd-creds seals the persistent copy to this
machine's host key. A replacement machine must fetch its own values from Trust.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess

OWNERS = {'dataservice.application.json': 0, 'postgres': 0, 'smtp': 0,
          'internal-service-key': 0, 'ingress.pem': 0,
          'ingress/ingress.pem': 0,
          'database/secrets/postgres': 1001, 'database/secrets/repmgr': 1001,
          'database/secrets/pgpool': 1001, 'database/certs/server.crt': 1001,
          'database/certs/server.key': 1001, 'database/certs/ca.crt': 1001,
          'monitoring/postgres': 65534, 'monitoring/grafana_admin_password': 472}
NAMES = set(OWNERS)
APPLICATION = {'dataservice.application.json', 'postgres', 'smtp', 'internal-service-key'}
DATABASE = {name for name in NAMES if name.startswith('database/')}


def command(argv, data=None):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Runtime credential operation failed; output suppressed')
    return result.stdout


def validate(document, company):
    if document.get('company') != company or document.get('schema_version') != 1:
        raise ValueError('Runtime credential bundle identity does not match this installation')
    values = document.get('files', {})
    if not isinstance(values, dict) or not values or not set(values).issubset(NAMES):
        raise ValueError('Unexpected runtime credential file set')
    if not APPLICATION.issubset(values) and not DATABASE.issubset(values):
        raise ValueError('A complete database or application credential set is required')
    for group in (APPLICATION, DATABASE):
        if group.intersection(values) and not group.issubset(values):
            raise ValueError('Incomplete runtime credential group')
    if any(not isinstance(value, str) for value in values.values()):
        raise ValueError('Invalid runtime credential payload')
    return values


def protect(document, config):
    raw = json.dumps(document).encode()
    if config['backend'] == 'host':
        return command(['systemd-creds', 'encrypt', '--with-key=host', '--name=runtime', '-', '-'], raw)
    if config['backend'] != 'gcp-kms':
        raise ValueError('Unknown runtime encryption backend')
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from uncloud_gcp import kms
    context = ('certlocker-runtime-v1:' + document['company']).encode()
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    envelope = {'schema_version': 1, 'backend': 'gcp-kms',
                'key': base64.b64encode(kms('encrypt', key, config, context)).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(AESGCM(key).encrypt(nonce, raw, context)).decode()}
    return json.dumps(envelope).encode()


def unprotect(cache, config, company):
    if config['backend'] == 'host':
        return json.loads(command(['systemd-creds', 'decrypt', '--name=runtime', str(cache), '-']))
    if config['backend'] != 'gcp-kms':
        raise ValueError('Unknown runtime encryption backend')
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from uncloud_gcp import kms
    envelope = json.loads(cache.read_bytes())
    if envelope.get('schema_version') != 1 or envelope.get('backend') != 'gcp-kms':
        raise ValueError('Encrypted runtime cache has an unexpected format')
    context = ('certlocker-runtime-v1:' + company).encode()
    decode = lambda name: base64.b64decode(envelope[name], validate=True)
    key = kms('decrypt', decode('key'), config, context)
    return json.loads(AESGCM(key).decrypt(decode('nonce'), decode('ciphertext'), context))


def private_parent(path, runtime):
    for parent in reversed(path.parents):
        if parent == runtime or runtime in parent.parents:
            if parent.is_symlink():
                raise ValueError('Refusing a symlink credential directory')
            parent.mkdir(exist_ok=True, mode=0o700)
    # Docker mounts the database subdirectories into uid 1001 containers.
    if 'database' in path.relative_to(runtime).parts:
        path.parent.chmod(0o750)
        os.chown(path.parent, 1001, 0)


def write(path, data, mode):
    if path.is_symlink():
        raise ValueError('Refusing a symlink credential path')
    if path.is_dir():
        path.rmdir()  # Only an empty Docker-created bind directory is removable.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode), 'wb') as out:
        out.write(data)
    path.chmod(mode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['seal', 'restore'])
    parser.add_argument('--company', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.company):
        raise ValueError('Invalid company')
    runtime = Path('/run/certlocker') / args.company
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    if command(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(runtime)]).strip() != b'tmpfs':
        raise ValueError('Runtime credential destination must be tmpfs')
    cache = Path('/var/lib/certlocker') / args.company / 'runtime.cred'
    cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = Path('/etc/certlocker') / args.company / 'runtime.json'
    config = json.loads(config_path.read_text())
    if args.action == 'seal':
        values = {name: (runtime / name).read_text() for name in NAMES if (runtime / name).is_file()}
        document = {'schema_version': 1, 'company': args.company, 'files': values}
        validate(document, args.company)
        encrypted = protect(document, config)
        temporary = cache.with_suffix('.new')
        write(temporary, encrypted, 0o600)
        temporary.replace(cache)
    else:
        document = unprotect(cache, config, args.company)
        for name, value in validate(document, args.company).items():
            private_parent(runtime / name, runtime)
            write(runtime / name, value.encode(), 0o400)
            os.chown(runtime / name, OWNERS[name], 0)
        (runtime / 'haproxy').mkdir(mode=0o700, exist_ok=True)
    print('Runtime credential', args.action, 'completed; values suppressed')


if __name__ == '__main__':
    main()
