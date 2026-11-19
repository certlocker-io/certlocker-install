#!/usr/bin/env python3
"""Change only selected image pins; preserve all unrelated containers and config."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import ipaddress
import urllib.request
from urllib.parse import quote

CLIENT_KINDS = {'dataservice': 'DATASERVICE', 'gateway': 'GATEWAY',
                'bastion-server': 'BASTION', 'edge': 'EDGE', 'backoffice-api': 'BACKOFFICE'}
INTERNAL_SERVICE_HEADER = 'X-CL-Internal-Service-Key'


def internal_service_headers(company):
    key = (Path('/run/certlocker') / company / 'internal-service-key').read_text().strip()
    if len(key) < 32:
        raise RuntimeError('Internal service authentication key is unavailable')
    return {INTERNAL_SERVICE_HEADER: key}


def router_nodes(router, company):
    request = urllib.request.Request(f'http://{router}:9000/router/rest/status',
                                     headers=internal_service_headers(company))
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)['nodes']


def quiesce_service(router, local, peer, service, company, seconds=30, settle_seconds=10):
    """Withdraw internal routing as well as the already drained public ingress."""
    kind = CLIENT_KINDS[service]
    nodes = router_nodes(router, company)
    if not any(n.get('host') == peer and n.get('type') == kind and n.get('status') == 'ACTIVE' for n in nodes):
        raise RuntimeError('The peer service must be ACTIVE before quiescing ' + service)
    targets = [n for n in nodes if n.get('host') == local and n.get('type') == kind
               and n.get('status') in ('ACTIVE', 'QUIESCED')]
    if len(targets) != 1:
        raise RuntimeError('Expected exactly one local registration before quiescing ' + service)
    target = targets[0]
    if target['status'] == 'ACTIVE':
        request = urllib.request.Request(
            f'http://{router}:9000/router/rest/registra/quiesce/' + quote(str(target['node_id']), safe=''),
            data=b'', method='POST', headers=internal_service_headers(company))
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    deadline = time.monotonic() + seconds
    while not any(n.get('node_id') == target['node_id'] and n.get('status') == 'QUIESCED'
                  for n in router_nodes(router, company)):
        if time.monotonic() >= deadline:
            raise RuntimeError('Internal service drainage did not converge; container preserved')
        time.sleep(1)
    # Public ingress is already drained; QUIESCED means Router stopped selecting this
    # instance. Default settle matches the established HA procedure; --fast splits a
    # 15s per-node budget across the services that actually quiesce.
    if settle_seconds > 0:
        time.sleep(settle_seconds)


def await_handoff(router, local, manifest, company, seconds=180, standby=False):
    """A Router change uses the clients' reconnect handler, never replacement."""
    wanted = {(kind, manifest['services'][service]['version'])
              for service, kind in CLIENT_KINDS.items()
              if not standby or kind not in ('EDGE', 'BACKOFFICE')}
    deadline = time.monotonic() + seconds
    while True:
        try:
            nodes = router_nodes(router, company)
            active = {(node['type'], node.get('version', '').split(' : ', 1)[0])
                      for node in nodes if node.get('host') == local and node.get('status') == 'ACTIVE'}
            if wanted.issubset(active):
                return
        except (OSError, ValueError, KeyError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('Router handoff did not register all local clients; containers preserved and ingress remains drained')
        time.sleep(2)

SERVICES = ('router', 'dataservice', 'gateway', 'bastion-server', 'edge',
            'backoffice-api', 'ui', 'backoffice-ui')


def run(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=900)
    if result.returncode:
        raise RuntimeError('Release operation failed; private command output suppressed: ' + args[0])
    return result.stdout


def patch_images(original, manifest, selected, registry_prefix=None):
    """Retain every byte outside the selected service image lines."""
    if registry_prefix is not None and not re.fullmatch(
            r'[a-z0-9-]+-docker\.pkg\.dev/[a-z][a-z0-9-]{4,28}[a-z0-9]/[a-z0-9][a-z0-9_-]*', registry_prefix):
        raise ValueError('Expected the installed customer registry prefix')
    service = None
    found = set()
    lines = original.splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = re.fullmatch(r'  ([a-z][a-z0-9-]*):\s*\n?', line)
        if match:
            service = match[1]
        elif line and not line[0].isspace() and not line.startswith('#'):
            service = None
        if service in selected and re.match(r'^    image:', line):
            if service in found:
                raise ValueError('Duplicate service image field')
            image = manifest['services'][service]['image']
            pattern = ((re.escape(registry_prefix + '/' + service) if registry_prefix else
                        r'ghcr\.io/certlocker-io/[a-z0-9/_.-]+') + r'@sha256:[0-9a-f]{64}')
            if not re.fullmatch(pattern, image):
                raise ValueError('Expected an immutable CertLocker application image')
            lines[index] = '    image: ' + image + '\n'
            found.add(service)
    if found != set(selected):
        raise ValueError('Selected services are missing from the installed Compose file')
    return ''.join(lines)


def containers():
    return {item['Names']: item['ID'] for item in
            map(json.loads, run(['docker', 'ps', '-a', '--no-trunc', '--format', '{{json .}}']).splitlines())}


def image_changed(service, manifest):
    # Read the running container, not just Compose: a failed earlier update can
    # leave the candidate pin on disk while the old process is still running.
    installed = run(['docker', 'inspect', 'certlocker-' + service,
                     '--format', '{{.Config.Image}}']).strip()
    return installed != manifest['services'][service]['image']


def require_preserved(before, after, selected):
    allowed = {'certlocker-' + name for name in selected}
    changed = sorted(name for name, identifier in before.items()
                     if name not in allowed and after.get(name) != identifier)
    if changed:
        raise RuntimeError('Unselected container identities changed: ' + ', '.join(changed))


def write_private(path, value):
    # These files contain installed configuration; never print or relax permissions.
    import os
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as stream:
        stream.write(value)
    path.chmod(0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['cached', 'stage', 'update'])
    parser.add_argument('--company', required=True)
    parser.add_argument('--selected', required=True, help='JSON service names, never credentials')
    parser.add_argument('--cached-only', action='store_true')
    parser.add_argument('--router-only', action='store_true')
    parser.add_argument('--reregister', action='store_true')
    parser.add_argument('--recreate', action='store_true')
    parser.add_argument('--handoff-only', action='store_true', help='Reconnect already upgraded clients without restarting them')
    parser.add_argument('--mesh-ip', help='Installed local mesh address for a handoff registration gate')
    parser.add_argument('--router-ip', help='Set the pre-staged Router address during a planned handoff')
    parser.add_argument('--quiesce-settle', type=int, default=10,
                        help='Seconds to wait after each service reaches QUIESCED (default 10)')
    parser.add_argument('--quiesce-settle-budget', type=int,
                        help='Split this many settle seconds across services that quiesce on this node')
    args = parser.parse_args(argv)
    if args.quiesce_settle < 0:
        parser.error('--quiesce-settle must be >= 0')
    if args.quiesce_settle_budget is not None and args.quiesce_settle_budget < 0:
        parser.error('--quiesce-settle-budget must be >= 0')
    if args.router_ip:
        args.router_ip = str(ipaddress.ip_address(args.router_ip))
    if args.handoff_only:
        if args.action != 'update' or not args.router_ip or not args.mesh_ip or args.router_only or args.recreate or args.reregister:
            parser.error('A handoff requires update, router-ip and mesh-ip, without replacement flags')
        args.mesh_ip = str(ipaddress.ip_address(args.mesh_ip))
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.company):
        raise ValueError('Invalid company')
    selected = json.loads(args.selected)
    if not isinstance(selected, list) or not selected or any(name not in SERVICES for name in selected):
        raise ValueError('Invalid application selection')
    root = Path('/opt/certlocker') / args.company / 'uncloud-apps'
    single_owner = re.search(r'^HA_API_SINGLE_OWNER=1$', (root / '.env').read_text(), re.M) is not None
    manifest = json.loads((root / 'release.candidate.json').read_text())
    # Setup pre-stages the profile-disabled Router on both machines.
    original = (root / 'compose.yaml').read_text()
    local = [name for name in selected if name != 'router' or '\n  router:\n' in original]
    registry_prefix = None
    registry_config = Path('/etc/certlocker/gcp-registry.json')
    if registry_config.exists():
        registry = json.loads(registry_config.read_text())
        registry_prefix = registry.get('registry_prefix', '')
        if registry_prefix.split('/')[0] != registry.get('registry_host'):
            raise ValueError('Customer registry prefix is missing or differs from the installed host; rerun setup')
    rendered = (root / 'compose.candidate.yaml').read_text()
    candidate = patch_images(rendered, manifest, local, registry_prefix)
    baseline = root / 'compose.before-release.sha256'
    installed_hash = hashlib.sha256(original.encode()).hexdigest()
    staged = root / 'compose.release.yaml'
    if args.action == 'cached':
        images = [manifest['services'][name]['image'] for name in local]
        result = subprocess.run(['docker', 'image', 'inspect', *images],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise SystemExit(0 if result.returncode == 0 else 1)
    if args.action == 'stage':
        write_private(staged, candidate)
        write_private(baseline, installed_hash)
        run(['docker', 'compose', '-f', str(staged), 'config', '--quiet'], cwd=root)
        if local and not args.cached_only:
            run(['docker', 'compose', '-f', str(staged), 'pull', '--quiet', *local], cwd=root)
        print(json.dumps({'staged': local}))
        return
    if (not staged.is_file() or staged.read_text() != candidate or
            (original != candidate and installed_hash != baseline.read_text())):
        raise ValueError('Installed Compose changed since image staging; restage before updating')
    partial_clients = (not args.router_only and not args.reregister and not args.handoff_only
                       and any(name in CLIENT_KINDS for name in local))
    if partial_clients:
        if not args.mesh_ip:
            raise ValueError('A Java service rollout requires its installed mesh address for internal drainage')
        args.mesh_ip = str(ipaddress.ip_address(args.mesh_ip))
        settings = json.loads((root.parent / 'uncloud-router-proxy/settings.json').read_text())
        if args.mesh_ip not in settings['nodes'].values():
            raise ValueError('Local address is outside the installed mesh pair')
        peer = next(address for address in settings['nodes'].values() if address != args.mesh_ip)
        current_router = settings['target']
    if args.handoff_only:
        if not re.search(r'^HA_ROUTER_PROXY=1$', (root / '.env').read_text(), re.M):
            raise ValueError('A non-disruptive handoff requires the installed stable Router proxy')
        settings = json.loads((root.parent / 'uncloud-router-proxy/settings.json').read_text())
        if args.mesh_ip not in settings['nodes'].values() or args.router_ip not in settings['nodes'].values():
            raise ValueError('Handoff addresses must belong to the installed mesh pair')
    before = containers()
    write_private(root / ('compose.before-release-' + str(time.time_ns()) + '.yaml'), original)
    write_private(root / 'compose.yaml', candidate)
    if args.router_ip:
        env_path = root / '.env'
        original_env = env_path.read_text()
        if not re.search(r'^HA_ROUTER_IP=', original_env, re.M):
            raise ValueError('Setup must install HA routing state before a Router handoff')
        write_private(env_path, re.sub(r'^HA_ROUTER_IP=.*$', 'HA_ROUTER_IP=' + args.router_ip,
                                      original_env, flags=re.M))
    updating = ['router'] if args.router_only else [name for name in SERVICES if name in local and name != 'router']
    if args.handoff_only:
        updating = []
    def will_quiesce(name):
        return (partial_clients and name in CLIENT_KINDS
                and not (single_owner and name in ('edge', 'backoffice-api'))
                and (args.recreate or image_changed(name, manifest)))
    quiescing = [name for name in updating if will_quiesce(name)]
    if args.quiesce_settle_budget is not None and quiescing:
        # Cap each service at the normal settle; budget is a per-node total ceiling.
        settle_seconds = max(1, min(args.quiesce_settle, args.quiesce_settle_budget // len(quiescing)))
    else:
        settle_seconds = args.quiesce_settle
    def switch_router():
        if args.router_ip and re.search(r'^HA_ROUTER_PROXY=1$', (root / '.env').read_text(), re.M):
            run(['/usr/local/sbin/certlocker-uncloud-router-proxy', 'select',
                 '--company', args.company, '--target', args.router_ip])
    try:
        if not args.router_only:
            switch_router()
        for name in updating:
            if name not in local:
                raise ValueError('Router update requested on a node without Router')
            if single_owner and name in ('edge', 'backoffice-api'):
                if not (root / '.api-owner-maintenance').exists():
                    raise RuntimeError('Owned API updates require local ownership maintenance')
                if run(['docker', 'inspect', 'certlocker-' + name, '--format', '{{.State.Running}}']).strip() != 'false':
                    raise RuntimeError('Owned API must be stopped before image replacement')
                command = ['docker', 'compose', '--profile', 'owned-api', 'create', '--pull', 'never']
                if args.recreate:
                    command.append('--force-recreate')
                run([*command, name], cwd=root)
                continue
            command = ['docker', 'compose', 'up', '-d', '--no-deps', '--pull', 'never',
                       '--timeout', '20', '--wait', '--wait-timeout', '300']
            quiesced = will_quiesce(name)
            if quiesced:
                quiesce_service(current_router, args.mesh_ip, peer, name, args.company,
                                settle_seconds=settle_seconds)
            if quiesced or args.recreate or (args.reregister and name not in ('router', 'ui', 'backoffice-ui')):
                command.append('--force-recreate')
            run([*command, name], cwd=root)
        if args.router_only:
            switch_router()
        if args.handoff_only:
            standby = single_owner and run(['docker', 'inspect', 'certlocker-edge', '--format', '{{.State.Running}}']).strip() == 'false'
            await_handoff(args.router_ip, args.mesh_ip, manifest, args.company, standby=standby)
    finally:
        require_preserved(before, containers(), updating)
    print(json.dumps({'updated': updating, 'unselected_containers_preserved': True}))


if __name__ == '__main__':
    main()
