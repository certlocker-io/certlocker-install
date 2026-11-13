#!/usr/bin/env python3
"""Refresh only DataService mail settings on an already drained origin."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def atomic_write(path, value, mode):
    if path.is_symlink():
        raise ValueError('Refusing a symlink runtime destination')
    fd, temporary = tempfile.mkstemp(prefix='.smtp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def smtp_environment(settings):
    enabled = settings['smtp_enabled']
    port = settings.get('smtp_port', 587)
    tls = settings.get('smtp_tls', 'starttls')
    if type(enabled) is not bool or type(port) is not int or not 1 <= port <= 65535 or tls not in ('tls', 'starttls'):
        raise ValueError('Invalid SMTP settings')
    if enabled and (not settings.get('smtp_host') or not settings.get('smtp_user')):
        raise ValueError('Enabled SMTP requires a host and username')
    return {'SmtpHost': settings['smtp_host'], 'SmtpUsername': settings['smtp_user'],
            'SmtpEnabled': str(enabled).lower(), 'SmtpPort': str(port),
            'SmtpSsl': str(tls == 'tls').lower(), 'SmtpStartTls': str(tls == 'starttls').lower()}


def patch_compose(original, settings):
    values = smtp_environment(settings)
    match = re.search(r'^  dataservice:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:|\Z)', original, re.M | re.S)
    if not match:
        raise ValueError('DataService missing from installed Compose')
    body = match['body']
    if len(re.findall(r'^    environment:\s*$', body, re.M)) != 1:
        raise ValueError('Expected one DataService environment block')
    for name in values:
        body = re.sub(r'^      ' + name + r':[^\n]*\n', '', body, flags=re.M)
    # Compose interpolates dollar signs even in quoted YAML values.
    additions = ''.join('      ' + name + ': ' + json.dumps(value.replace('$', '$$')) + '\n'
                        for name, value in values.items())
    body = body.replace('    environment:\n', '    environment:\n' + additions, 1)
    return original[:match.start('body')] + body + original[match.end('body'):]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--company', required=True)
    parser.add_argument('--settings', required=True, help='Non-secret SMTP settings JSON')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.company):
        raise ValueError('Invalid company')
    settings = json.loads(args.settings)
    root = Path('/opt/certlocker') / args.company / 'uncloud-apps'
    runtime = Path('/run/certlocker') / args.company
    config_path = runtime / 'dataservice.application.json'
    if subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(runtime)]).strip() != b'tmpfs':
        raise ValueError('Runtime mail credentials must remain on tmpfs')
    config = json.loads(config_path.read_text())
    mail = config['email_server_config']
    mail.update(smtp_host='${SmtpHost:}', smtp_username='${SmtpUsername:}', smtp_port='${SmtpPort:587}',
                smtp_password='${SmtpPassword:}', smtp_ssl='${SmtpSsl:false}',
                start_tls='${SmtpStartTls:true}', enabled='${SmtpEnabled:false}', auth=True, ssl_trust='')
    candidates = {path: patch_compose(path.read_text(), settings)
                  for path in (root / 'compose.yaml', root / 'compose.release.yaml')}
    # Validate both documents before replacing either installed or staged config.
    for candidate in candidates.values():
        result = subprocess.run(['docker', 'compose', '-f', '-', 'config', '--quiet'],
                                cwd=root, input=candidate, text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('SMTP Compose validation failed; output suppressed')
    for path, candidate in candidates.items():
        atomic_write(path, candidate.encode(), 0o600)
    atomic_write(config_path, json.dumps(config).encode(), 0o400)
    result = subprocess.run(['/usr/local/sbin/certlocker-uncloud-runtime', 'seal', '--company', args.company],
                            capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('SMTP encrypted boot cache update failed; output suppressed')
    print('DataService mail settings refreshed and encrypted boot cache sealed')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('SMTP runtime refresh failed; private output suppressed')
