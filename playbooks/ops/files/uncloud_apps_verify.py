#!/usr/bin/env python3
"""Verify pinned application images and real HTTP/registration health; emit no secrets."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

KINDS = {'DATASERVICE': ('dataservice', 8200, 'dataservice'),
         'GATEWAY': ('gateway', 8300, 'gateway'),
         'BASTION': ('bastion-server', 8400, 'bastion'),
         'EDGE': ('edge', 8500, 'edge'),
         'BACKOFFICE': ('backoffice-api', 8600, 'backoffice')}
INTERNAL_SERVICE_HEADER = 'X-CL-Internal-Service-Key'


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Docker verification operation failed; diagnostic suppressed')
    return result.stdout.strip()


def internal_service_headers(company):
    key = (Path('/run/certlocker') / company / 'internal-service-key').read_text().strip()
    if len(key) < 32:
        raise RuntimeError('Internal service authentication key is unavailable')
    return {INTERNAL_SERVICE_HEADER: key}


def get(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read()


def expected_registrations(spec, hosts, owner=None):
    return {(host, kind, spec['services'][service]['version'])
            for host in hosts for kind, (service, _, _) in KINDS.items()
            if owner is None or kind not in ('EDGE', 'BACKOFFICE') or host == owner}


def serving_owner(hosts, seconds=240):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready = []
        for host in hosts:
            try:
                code, body = get(f'http://{host}:8510/ready')
                if code == 200 and json.loads(body).get('success') is True:
                    ready.append(host)
            except (OSError, ValueError):
                pass
        if len(ready) == 1:
            return ready[0]
        if len(ready) > 1:
            raise RuntimeError('Multiple application owners are serving')
        time.sleep(2)
    raise RuntimeError('No application owner became ready')


def active_registrations(nodes):
    return {(node['host'], node['type'], node.get('version', '').split(' : ', 1)[0])
            for node in nodes if node.get('status') == 'ACTIVE'}


class ReadinessPending(RuntimeError):
    pass


def inspect_pinned_container(service, image, standby=False):
    deadline = time.monotonic() + 60
    fields = '{"image":{{json .Config.Image}},"running":{{json .State.Running}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}}}'
    while True:
        data = json.loads(docker('inspect', 'certlocker-' + service, '--format', fields))
        if data['image'] != image:
            raise RuntimeError('Unexpected application image: ' + service)
        if (not data['running'] if standby else data['running'] and data['health'] == 'healthy'):
            return
        if time.monotonic() >= deadline:
            raise ReadinessPending('Container health or ownership has not settled: ' + service)
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mesh-ip', required=True)
    parser.add_argument('--router-ip', required=True)
    parser.add_argument('--peer-ip', required=True)
    parser.add_argument('--company', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--primary', action='store_true')
    parser.add_argument('--node-only', action='store_true', help='Gate a rolling update before changing the other node')
    args = parser.parse_args()
    env = dict(line.split('=', 1) for line in
               (Path('/opt/certlocker') / args.company / 'uncloud-apps/.env').read_text().splitlines()
               if line and not line.startswith('#'))
    single_owner = env.get('HA_API_SINGLE_OWNER') == '1'
    owner = serving_owner([args.mesh_ip, args.peer_ip]) if single_owner else None
    if args.router_ip == 'current':
        env = dict(line.split('=', 1) for line in
                   (Path('/opt/certlocker') / args.company / 'uncloud-apps/.env').read_text().splitlines()
                   if line and not line.startswith('#'))
        args.router_ip = env['HA_ROUTER_IP']
        args.primary = args.router_ip == args.mesh_ip
        if env.get('HA_ROUTER_PROXY') == '1':
            result = subprocess.run(['/usr/local/sbin/certlocker-uncloud-router-proxy', 'verify',
                                     '--company', args.company, '--target', args.router_ip],
                                    capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError('Stable Router endpoint failed verification')
    spec = json.loads(Path(args.manifest).read_text())
    report = {'company': args.company, 'release': spec['release'], 'images': {}, 'http_health': {}, 'registry': 'pending'}
    expected = {service: value for service, value in spec['services'].items()
                if service != 'router' or args.primary}
    for service, value in expected.items():
        standby_api = single_owner and owner != args.mesh_ip and service in ('edge', 'backoffice-api')
        inspect_pinned_container(service, value['image'], standby_api)
        report['images'][service] = 'pinned-cold-standby' if standby_api else 'pinned-and-healthy'
    for kind, (service, port, context) in KINDS.items():
        if single_owner and owner != args.mesh_ip and kind in ('EDGE', 'BACKOFFICE'):
            continue
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                code, body = get(f'http://{args.mesh_ip}:{port}/{context}/rest/health')
                if code == 200 and json.loads(body).get('success') is True:
                    break
            except (OSError, urllib.error.URLError, json.JSONDecodeError):
                pass
            time.sleep(3)
        else:
            raise RuntimeError('Application HTTP health did not become ready: ' + service)
        report['http_health'][service] = 'passed'
    for service, port in [('ui', 3080), ('backoffice-ui', 3081)]:
        for path in ('/', '/internal/haproxy-ready'):
            if path != '/' and single_owner and owner != args.mesh_ip:
                continue
            code, body = get(f'http://127.0.0.1:{port}{path}')
            if code != 200:
                raise RuntimeError('UI route failed: ' + service)
        report['http_health'][service] = 'passed'
    schema_count = docker('exec', 'certlocker-uncloud-postgres', 'bash', '-ec',
        'export PGPASSWORD="$(cat /run/lab-secrets/postgres)" PGSSLMODE=disable; '
        'exec psql -h pgpool -U postgres -d certlocker -At -v ON_ERROR_STOP=1 -c '
        '"SELECT count(*) FROM information_schema.tables WHERE table_schema=\'jeremy\' '
        'AND table_name IN (\'accounts\',\'users\',\'certs\',\'secrets\',\'tokens\')"')
    if schema_count != '5':
        raise RuntimeError('Expected application schema is not available through Pgpool')
    report['application_schema_through_pgpool'] = 'passed'
    wanted = expected_registrations(spec, [args.mesh_ip] if args.node_only else [args.mesh_ip, args.peer_ip], owner)
    registry_headers = internal_service_headers(args.company)
    for attempt in range(60):
        try:
            code, body = get(f'http://{args.router_ip}:9000/router/rest/status', registry_headers)
            nodes = json.loads(body)['nodes']
            api_hosts = {node.get('host') for node in nodes if node.get('type') in ('EDGE', 'BACKOFFICE')
                         and node.get('status') == 'ACTIVE'}
            if wanted.issubset(active_registrations(nodes)) and (not single_owner or
                    (args.node_only and owner != args.mesh_ip) or api_hosts == {owner}):
                break
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            pass
        time.sleep(3)
    else:
        raise RuntimeError('Both nodes did not register ACTIVE at the intended image versions')
    report['registry'] = 'node-active-at-pinned-versions' if args.node_only else 'both-nodes-active-at-pinned-versions'
    if single_owner:
        if serving_owner([args.mesh_ip, args.peer_ip]) != owner:
            raise ReadinessPending('Application ownership changed during verification')
        report.update(application_owner=owner, registry='single-api-owner-and-active-shared-services')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except ReadinessPending as error:
        print(str(error), file=sys.stderr)
        sys.exit(75)
