#!/usr/bin/env python3
"""Migrate installed deployment configuration without reading Trust credentials."""
import argparse
import os
from pathlib import Path
import re
import subprocess


def compose_config(text):
    for name in ('edge', 'backoffice-api'):
        pattern = r'(?ms)^  ' + re.escape(name) + r':\n.*?(?=^  [a-z][a-z0-9-]*:\n|^[a-z]|\Z)'
        match = re.search(pattern, text)
        if not match:
            raise ValueError('Missing installed API service: ' + name)
        block = match.group()
        block = re.sub(r'^    (profiles|restart):.*\n', '', block, flags=re.M)
        block = block.replace('    <<: *java\n', "    <<: *java\n    profiles: [owned-api]\n    restart: 'no'\n", 1)
        if 'profiles: [owned-api]' not in block:
            raise ValueError('Unexpected installed Compose structure')
        text = text[:match.start()] + block + text[match.end():]
    return text


def ingress_config(text):
    for name, port in (('be_ui', 3080), ('be_bo', 3081)):
        pattern = r'(?ms)^backend ' + name + r'\n.*?(?=^backend |\Z)'
        match = re.search(pattern, text)
        if not match:
            raise ValueError('Missing installed ingress backend: ' + name)
        block = match.group()
        if 'http-check connect port 8510' in block:
            continue
        checks = ('    http-check connect port 8510\n'
                  '    http-check send meth GET uri /ready ver HTTP/1.1 hdr Host localhost\n'
                  '    http-check expect status 200\n'
                  '    http-check expect rstring \'"success"[[:space:]]*:[[:space:]]*true\'\n'
                  f'    http-check connect port {port}\n')
        if '    option httpchk\n' not in block:
            raise ValueError('Missing installed HTTP readiness check')
        block = block.replace('    option httpchk\n', '    option httpchk\n' + checks, 1)
        text = text[:match.start()] + block + text[match.end():]
    return text


def write(path, text):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as stream:
        stream.write(text)


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError('Configuration validation failed; private output suppressed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['apps', 'ingress'])
    p.add_argument('--company', required=True)
    args = p.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', args.company):
        raise ValueError('Invalid company')
    base = Path('/opt/certlocker') / args.company
    path = base / ('uncloud-apps/compose.yaml' if args.action == 'apps' else 'uncloud-ingress/haproxy.cfg')
    old = path.read_text()
    new = (compose_config if args.action == 'apps' else ingress_config)(old)
    candidate = path.with_name('owner-candidate.' + path.name)
    write(candidate, new)
    if args.action == 'apps':
        command(['docker', 'compose', '-f', str(candidate), 'config', '--quiet'], cwd=path.parent)
    else:
        command(['docker', 'exec', 'certlocker-haproxy', 'haproxy', '-c', '-f',
                 '/usr/local/etc/haproxy/' + candidate.name])
    backup = path.with_name(path.name + '.before-single-owner')
    if not backup.exists():
        write(backup, old)
    candidate.replace(path)
    if args.action == 'apps':
        env = path.parent / '.env'
        text = re.sub(r'^HA_API_SINGLE_OWNER=.*\n?', '', env.read_text(), flags=re.M)
        write(env, text.rstrip() + '\nHA_API_SINGLE_OWNER=1\n')
    elif new != old:
        # Docker's kill API marks even a non-fatal signal as a manual stop,
        # which prevents an unless-stopped container returning after reboot.
        command(['docker', 'exec', 'certlocker-haproxy',
                 'sh', '-c', 'kill -USR2 1'])
    print('Installed ' + args.action + ' ownership configuration; Java unchanged.')


if __name__ == '__main__':
    main()
