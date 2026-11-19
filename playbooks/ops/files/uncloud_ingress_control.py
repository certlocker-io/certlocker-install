#!/usr/bin/env python3
"""Drain one node through the running HAProxy socket without replacing HAProxy."""
import argparse
import csv
import io
import re
import socket
import time
from pathlib import Path
import json

BACKENDS = ('be_ui', 'be_bo', 'be_gateway')


def command(path, value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(path)
        connection.sendall((value + '\n').encode())
        connection.shutdown(socket.SHUT_WR)
        parts = []
        while True:
            data = connection.recv(65536)
            if not data:
                break
            parts.append(data)
    return b''.join(parts).decode()


def ready(path, node, owner_aware=False):
    rows = list(csv.DictReader(io.StringIO(command(path, 'show stat').removeprefix('# '))))
    return all(any(row['pxname'] == backend and
                   (row['svname'] == node or (owner_aware and backend in ('be_ui', 'be_bo') and
                                             row['svname'] not in ('BACKEND', 'FRONTEND'))) and
                   row['status'] == 'UP' and row['check_status'] == 'L7OK'
                   for row in rows) for backend in BACKENDS)


def wait_ready(path, node, seconds=90):
    deadline = time.monotonic() + seconds
    consecutive = 0
    while time.monotonic() < deadline:
        consecutive = consecutive + 1 if ready(path, node) else 0
        if consecutive >= 2:
            return
        time.sleep(1)
    raise RuntimeError('Node must pass every HAProxy L7 check consistently before traffic changes')


def current_sessions(path, node):
    rows = list(csv.DictReader(io.StringIO(command(path, 'show stat').removeprefix('# '))))
    return sum(int(row.get('scur') or 0) for row in rows
               if row.get('pxname') in BACKENDS and row.get('svname') == node)


def wait_drained(path, node, seconds=15):
    """Wait until HAProxy reports no current sessions on the drained backends."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if current_sessions(path, node) == 0:
            return
        time.sleep(0.5)
    raise RuntimeError('Active requests remain after draining; rollout stopped before replacing containers')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'drain', 'ready'])
    parser.add_argument('--company', required=True)
    parser.add_argument('--node', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.company):
        raise ValueError('Invalid company')
    path = '/run/certlocker/' + args.company + '/haproxy/admin.sock'
    env = Path('/opt/certlocker') / args.company / 'uncloud-apps/.env'
    owner_aware = env.exists() and 'HA_API_SINGLE_OWNER=1' in env.read_text().splitlines()
    nodes = json.loads((env.parent.parent / 'uncloud-router-proxy/settings.json').read_text())['nodes']
    if len(nodes) != 2 or args.node not in nodes:
        raise ValueError('Node is outside the installed pair')
    peer = next(node for node in nodes if node != args.node)
    if args.action == 'check':
        wait_ready(path, args.node)
        print(args.node, 'passed stable L7 checks')
        return
    if args.action == 'drain':
        wait_ready(path, peer)
    for backend in BACKENDS:
        response = command(path, f'set server {backend}/{args.node} state {args.action}')
        if response.strip():
            raise RuntimeError('HAProxy refused runtime state change')
    if args.action == 'ready':
        deadline = time.monotonic() + 90
        while not ready(path, args.node, owner_aware=owner_aware):
            if time.monotonic() >= deadline:
                for backend in BACKENDS:
                    command(path, f'set server {backend}/{args.node} state drain')
                raise RuntimeError('Updated backends failed L7 gates; node left drained')
            time.sleep(1)
    else:
        wait_drained(path, args.node)
    print(args.node, args.action, 'through running HAProxy')


if __name__ == '__main__':
    main()
