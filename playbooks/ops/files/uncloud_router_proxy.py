#!/usr/bin/env python3
"""Keep local Router endpoints stable while switching the elected backend.

Only the two provisioned mesh addresses are accepted. Runtime changes close the
old registration sessions so the released clients reconnect and register again.
The selected address is persisted without credentials for container restarts.
"""
import argparse
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import urllib.request

BACKENDS = ('router_http', 'router_registration')


def private_write(path, value):
    temporary = path.with_suffix('.new')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as out:
        out.write(value)
    temporary.replace(path)


def validate(settings):
    nodes = settings.get('nodes', {})
    if len(nodes) != 2 or sorted(nodes)[1] != sorted(nodes)[0][:-1] + 'b' or not sorted(nodes)[0].endswith('-a'):
        raise ValueError('Exactly the two provisioned Router nodes are required')
    addresses = [str(ipaddress.ip_address(value)) for value in nodes.values()]
    if len(set(addresses)) != 2 or any(not ipaddress.ip_address(value).is_private for value in addresses):
        raise ValueError('Distinct private mesh addresses are required')
    if settings.get('target') not in addresses:
        raise ValueError('Router target is outside the installed pair')
    return settings


def configuration(settings):
    validate(settings)
    lines = ['global', '  stats socket /run/haproxy/admin.sock mode 600 level admin',
             '  tune.lua.bool-sample-conversion normal',
             '  lua-load /usr/local/etc/haproxy/wait-for-router.lua',
             '  tune.lua.session-timeout 600s',
             '  maxconn 1024', 'defaults', '  mode tcp', '  timeout connect 3s',
             '  timeout client 24h', '  timeout server 24h',
             'frontend router_http_local', '  bind 127.0.0.1:19000',
             '  default_backend router_http',
             'frontend router_registration_local', '  bind 127.0.0.1:41905',
             '  tcp-request inspect-delay 600s',
             '  tcp-request content lua.wait-for-router router_registration',
             '  default_backend router_registration',
             'frontend proxy_liveness', '  bind 127.0.0.1:19002', '  mode http',
             '  http-request return status 200 content-type text/plain string alive']
    for backend, port in [('router_http', 9000), ('router_registration', 40905)]:
        lines += ['backend ' + backend, '  option httpchk GET /router/rest/health',
                  '  http-check expect status 200']
        for node, address in settings['nodes'].items():
            disabled = '' if address == settings['target'] else ' disabled'
            lines.append(f'  server {node} {address}:{port} check port 9000 inter 1s fall 2 rise 1{disabled}')
    return '\n'.join(lines) + '\n'


def command(path, value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        connection.sendall((value + '\n').encode())
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while block := connection.recv(65536):
            chunks.append(block)
    return b''.join(chunks).decode()


def selected(path, settings):
    rows = list(csv.DictReader(io.StringIO(command(path, 'show stat').removeprefix('# '))))
    for backend in BACKENDS:
        for node, address in settings['nodes'].items():
            matches = [row for row in rows if row['pxname'] == backend and row['svname'] == node]
            if len(matches) != 1:
                return False
            enabled = not matches[0]['status'].startswith('MAINT')
            if enabled != (address == settings['target']):
                return False
    return True


def switch(root, socket_path, target):
    settings = validate(json.loads((root / 'settings.json').read_text()))
    previous = settings['target']
    if target not in settings['nodes'].values():
        raise ValueError('Refusing a Router outside the installed pair')
    with urllib.request.urlopen(f'http://{target}:9000/router/rest/health', timeout=3) as response:
        if json.load(response).get('success') is not True:
            raise RuntimeError('Selected Router is not healthy')
    settings['target'] = target
    # Reconcile the socket even when the persisted choice already matches: a
    # previous operation may have lost its connection partway through switching.
    if selected(socket_path, settings):
        if previous != target:
            private_write(root / 'config/haproxy.cfg', configuration(settings))
            private_write(root / 'settings.json', json.dumps(settings))
        return False
    private_write(root / 'config/haproxy.cfg', configuration(settings))
    private_write(root / 'settings.json', json.dumps(settings))
    for backend in BACKENDS:
        for node, address in settings['nodes'].items():
            if address != target:
                reply = command(socket_path, f'set server {backend}/{node} state maint')
                if reply.strip():
                    raise RuntimeError('Router proxy refused to disable old backend')
        node = next(node for node, address in settings['nodes'].items() if address == target)
        if command(socket_path, f'set server {backend}/{node} state ready').strip():
            raise RuntimeError('Router proxy refused to enable elected backend')
        for old, address in settings['nodes'].items():
            if address != target and command(socket_path, f'shutdown sessions server {backend}/{old}').strip():
                raise RuntimeError('Router proxy refused to close old sessions')
    if not selected(socket_path, settings):
        raise RuntimeError('Router proxy selection did not converge')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['bootstrap', 'select', 'verify'])
    parser.add_argument('--company', required=True)
    parser.add_argument('--target')
    parser.add_argument('--node-a')
    parser.add_argument('--node-b')
    parser.add_argument('--node-a-name')
    parser.add_argument('--node-b-name')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.company):
        raise ValueError('Invalid company')
    root = Path('/opt/certlocker') / args.company / 'uncloud-router-proxy'
    socket_path = Path('/run/certlocker') / args.company / 'router-proxy/admin.sock'
    if args.action == 'bootstrap':
        settings = validate({'nodes': {args.node_a_name or args.company+'-a': args.node_a, args.node_b_name or args.company+'-b': args.node_b}, 'target': args.target})
        if (root / 'settings.json').exists():
            existing = validate(json.loads((root / 'settings.json').read_text()))
            if existing['nodes'] != settings['nodes']:
                raise ValueError('Existing proxy belongs to a different mesh pair')
            settings = existing
        (root / 'config').mkdir(parents=True, exist_ok=True, mode=0o700)
        changed = False
        for path, value in [(root / 'settings.json', json.dumps(settings)),
                            (root / 'config/haproxy.cfg', configuration(settings))]:
            if not path.exists() or path.read_text() != value:
                private_write(path, value)
                changed = True
        print(json.dumps({'target': settings['target'], 'configured': True, 'changed': changed}))
    elif args.action == 'select':
        changed = switch(root, socket_path, args.target)
        print(json.dumps({'target': args.target, 'changed': changed}))
    else:
        settings = validate(json.loads((root / 'settings.json').read_text()))
        if settings['target'] != args.target or not selected(socket_path, settings):
            raise RuntimeError('Router proxy differs from elected target')
        with urllib.request.urlopen('http://127.0.0.1:19000/router/rest/health', timeout=3) as response:
            if json.load(response).get('success') is not True:
                raise RuntimeError('Local Router endpoint is not healthy')
        print(json.dumps({'target': args.target, 'verified': True}))


if __name__ == '__main__':
    main()
