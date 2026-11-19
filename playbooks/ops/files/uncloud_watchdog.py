#!/usr/bin/env python3
"""Follow the database role and repair Router registrations on an installed HA node.

Ports, dependency ordering and registration checks follow ha/watchdog.sh. This
adapter uses Uncloud mesh addresses and FILE credentials. It never promotes a
database or pulls an image. A failed DB query is not evidence of a role change.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request

CLIENTS = {'DATASERVICE': ('dataservice', 8200, 'dataservice'),
           'GATEWAY': ('gateway', 8300, 'gateway'),
           'BASTION': ('bastion-server', 8400, 'bastion'),
           'EDGE': ('edge', 8500, 'edge'),
           'BACKOFFICE': ('backoffice-api', 8600, 'backoffice')}
INTERNAL_SERVICE_HEADER = 'X-CL-Internal-Service-Key'


def run(argv, cwd=None, timeout=330):
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('HA operation timed out: ' + argv[0] + '; private output suppressed') from None
    if result.returncode:
        raise RuntimeError('HA operation failed: ' + argv[0] + '; private output suppressed')
    return result.stdout.strip()


def query(sql, pool=False):
    # Password never leaves the database container or enters argv.
    host = 'pgpool' if pool else '127.0.0.1'
    return run(['docker', 'exec', 'certlocker-uncloud-postgres', 'bash', '-ec',
                'export PGPASSWORD="$(cat /run/lab-secrets/postgres)" PGCONNECT_TIMEOUT=3 '
                f'PGSSLMODE={"disable" if pool else "require"}; '
                # PGCONNECT_TIMEOUT alone does not bound a Pgpool connection
                # which accepts TCP but waits for an unavailable backend. Kill
                # the query inside the container as well as bounding Docker.
                f'exec timeout --kill-after=1 6s psql -h {host} -U postgres -d certlocker -At -v ON_ERROR_STOP=1 -c "$1"',
                'query', sql], timeout=10)


def desired_router(recovery, local, peer):
    if recovery == 'f':
        return local
    if recovery == 't':
        return peer
    raise RuntimeError('Database role unknown; keep current routing')


def repair_services(nodes, local):
    active = {n.get('type') for n in nodes
              if n.get('host') == local and n.get('status') == 'ACTIVE'}
    if 'DATASERVICE' not in active:
        return [item[0] for item in CLIENTS.values()]
    return [service for kind, (service, _, _) in CLIENTS.items() if kind not in active]


def read_env(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line and not line.startswith('#'))


def save_env(path, values):
    temporary = path.with_suffix('.new')
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), 'w') as out:
        out.write(''.join(f'{key}={value}\n' for key, value in values.items()))
    temporary.replace(path)


def internal_service_headers(company):
    key = (Path('/run/certlocker') / company / 'internal-service-key').read_text().strip()
    if len(key) < 32:
        raise RuntimeError('Internal service authentication key is unavailable')
    return {INTERNAL_SERVICE_HEADER: key}


def get(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=4) as response:
        return json.load(response)


def router_status(target, company):
    return get(f'http://{target}:9000/router/rest/status', headers=internal_service_headers(company))


def healthy(url):
    try:
        return get(url).get('success') is True
    except (OSError, ValueError):
        return False


def wait_health(url, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if healthy(url):
            return
        time.sleep(2)
    raise RuntimeError('Application health did not converge; next timer tick will retry')


def wait_database(seconds=90, expected_role=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if expected_role is not None and query('SELECT pg_is_in_recovery()') != expected_role:
            raise RuntimeError('Database role changed while waiting for Pgpool; reconcile the new role on the next tick')
        try:
            if query('SELECT NOT pg_is_in_recovery()', pool=True) == 't':
                return
        except RuntimeError:
            pass
        time.sleep(3)
    raise RuntimeError('Pgpool not query-ready; do not restart Java clients yet')


def save_pending(path, state):
    temporary = path.with_suffix('.new')
    temporary.write_text(json.dumps(state))
    temporary.chmod(0o600)
    temporary.replace(path)


def read_pending(path):
    if not path.exists():
        return None
    raw = path.read_text()
    if raw in ('', 'pool-ready'):
        return {'phase': 'clients' if raw else 'pool',
                'remaining': [item[0] for item in CLIENTS.values()]}
    state = json.loads(raw)
    if (state.get('phase') not in ('pool', 'clients') or
            not isinstance(state.get('remaining'), list) or
            set(state['remaining']) - {item[0] for item in CLIENTS.values()}):
        raise RuntimeError('Invalid recovery progress; refusing to guess completed work')
    return state


def restart_wave(root, compose, services, local, target, pending, state, seconds=90):
    """Start independent clients together; retain each successful registration."""
    company = root.parent.name
    started = time.monotonic()
    waiting = set(services)
    attempted = set(state.get('attempted', []))
    if waiting & attempted:
        # A slow registration may finish between timer ticks. Do not destroy
        # that now-healthy process just because the previous wait expired.
        nodes = router_status(target, company)['nodes']
        active = {n.get('type') for n in nodes if n.get('host') == local and n.get('status') == 'ACTIVE'}
        for kind, (service, port, context) in CLIENTS.items():
            if (service in waiting & attempted and kind in active and
                    healthy(f'http://{local}:{port}/{context}/rest/health')):
                waiting.remove(service)
                state['remaining'].remove(service)
        save_pending(pending, state)
    if not waiting:
        return
    selected = [service for service in services if service in waiting]
    state['attempted'] = sorted(attempted | waiting)
    save_pending(pending, state)
    run([*compose, 'up', '-d', '--no-deps', '--pull', 'never', '--force-recreate',
         '--timeout', '2', *selected], cwd=root)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            nodes = router_status(target, company)['nodes']
            active = {n.get('type') for n in nodes if n.get('host') == local and n.get('status') == 'ACTIVE'}
        except (OSError, ValueError, KeyError):
            active = set()
        for kind, (service, port, context) in CLIENTS.items():
            if service in waiting and kind in active and healthy(f'http://{local}:{port}/{context}/rest/health'):
                waiting.remove(service)
                state['remaining'].remove(service)
                save_pending(pending, state)
        if not waiting:
            print(json.dumps({'stage': 'registered', 'services': services,
                              'seconds': round(time.monotonic() - started, 3)}), flush=True)
            return
        time.sleep(2)
    raise RuntimeError('Client registration did not converge; next tick retries only unfinished clients')


def client_processes():
    """Read process identities only, never container environment or credentials."""
    names = set(run(['docker', 'ps', '-a', '--format', '{{.Names}}']).splitlines())
    selected = ['certlocker-' + item[0] for item in CLIENTS.values()
                if 'certlocker-' + item[0] in names]
    if not selected:
        return {}
    template = ('{"name":{{json .Name}},"id":{{json .Id}},'
                '"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}}}')
    rows = run(['docker', 'inspect', '--format', template, *selected])
    result = {}
    for line in rows.splitlines():
        row = json.loads(line)
        if row['running']:
            result[row['name'].removeprefix('/certlocker-')] = {
                'id': row['id'], 'started_at': row['started_at']}
    return result


def healthy_survivors(path, current, missing):
    if not path.exists():
        return []
    receipt = json.loads(path.read_text())
    clients = receipt.get('clients')
    if (receipt.get('version') != 1 or not isinstance(clients, dict) or
            set(clients) - {item[0] for item in CLIENTS.values()} or
            any(not isinstance(value, dict) or set(value) != {'id', 'started_at'} or
                any(not isinstance(field, str) or not field for field in value.values())
                for value in clients.values())):
        raise RuntimeError('Invalid healthy-client receipt; refusing destructive recovery')
    return [service for service in missing if service in current and
            receipt['clients'].get(service) == current[service]]


def await_native_clients(local, target, company, seconds=90, expected_role=None):
    """Give the released reconnect handler time to rebuild the registry itself."""
    deadline = time.monotonic() + seconds
    remaining = [item[0] for item in CLIENTS.values()]
    statuses, health = {}, {}
    while True:
        if expected_role is not None and query('SELECT pg_is_in_recovery()') != expected_role:
            raise RuntimeError('Database role changed during native registration; reconcile before repairing clients')
        try:
            nodes = router_status(target, company)['nodes']
            usable = []
            statuses = {kind: sorted({node.get('status', 'UNKNOWN') for node in nodes
                                     if node.get('host') == local and node.get('type') == kind})
                        for kind in CLIENTS}
            health = {}
            for node in nodes:
                if node.get('host') != local or node.get('status') != 'ACTIVE':
                    continue
                entry = CLIENTS.get(node.get('type'))
                if entry:
                    health[entry[0]] = healthy(f'http://{local}:{entry[1]}/{entry[2]}/rest/health')
                    if health[entry[0]]:
                        usable.append(node)
            active = {node.get('type') for node in usable}
            remaining = [service for kind, (service, _, _) in CLIENTS.items() if kind not in active]
        except (OSError, ValueError, KeyError):
            pass
        if not remaining or time.monotonic() >= deadline:
            if remaining:
                print(json.dumps({'stage': 'native-registration-incomplete',
                                  'statuses': statuses, 'http_health': health,
                                  'remaining': remaining}), flush=True)
            return remaining
        time.sleep(1)


def reconcile(root, local, peer):
    global CLIENTS
    company = root.parent.name
    env_path = root / '.env'
    env = read_env(env_path)
    if env.get('HA_API_SINGLE_OWNER') == '1':
        # The dedicated owner alone starts/stops the interactive APIs.
        CLIENTS = {kind: value for kind, value in CLIENTS.items() if kind not in ('EDGE', 'BACKOFFICE')}
        old_receipt = root / '.native-healthy-clients.json'
        if old_receipt.exists():
            receipt = json.loads(old_receipt.read_text())
            if receipt.get('version') == 1 and isinstance(receipt.get('clients'), dict):
                receipt['clients'] = {key: value for key, value in receipt['clients'].items()
                                      if key not in ('edge', 'backoffice-api')}
                save_pending(old_receipt, receipt)
        old_pending = root / '.role-repair-pending'
        if old_pending.exists():
            raw = old_pending.read_text()
            # Older installations used an empty marker or "pool-ready".
            # Decode those through the same compatibility path as normal repair.
            previous = read_pending(old_pending) if raw in ('', 'pool-ready') else json.loads(raw)
            for key in ('remaining', 'attempted'):
                if isinstance(previous.get(key), list):
                    previous[key] = [s for s in previous[key] if s not in ('edge', 'backoffice-api')]
            save_pending(old_pending, previous)
    recovery = query('SELECT pg_is_in_recovery()')
    target = desired_router(recovery, local, peer)
    role = 'ha-primary' if recovery == 'f' else 'ha-secondary'
    changed = env.get('HA_ROUTER_IP') != target or env.get('HA_DB_ROLE') != role
    stable_proxy = env.get('HA_ROUTER_PROXY') == '1'
    pending = root / '.role-repair-pending'
    healthy_receipt = root / '.native-healthy-clients.json'
    compose = ['docker', 'compose', '--profile', 'ha-primary']
    if changed:
        # Durable retry marker precedes the env change: a failed repair must not
        # appear complete on the next tick or after a controller disconnection.
        save_pending(pending, {'phase': 'pool', 'remaining': [item[0] for item in CLIENTS.values()]})
        env.update(HA_ROUTER_IP=target, HA_DB_ROLE=role)
        save_env(env_path, env)
    running = ''
    if recovery == 't':
        # Explicit removal prevents a stale local registry on node return.
        running = run(['docker', 'ps', '-a', '--filter', 'name=^/certlocker-router$', '--format', '{{.Names}}'])
        if running and not stable_proxy:
            run([*compose, 'stop', '-t', '5', 'router'], cwd=root)
            run([*compose, 'rm', '-f', 'router'], cwd=root)
    elif not healthy(f'http://{local}:9000/router/rest/health'):
        run([*compose, 'up', '-d', '--no-deps', '--pull', 'never', 'router'], cwd=root)
    # An unreachable peer must not hide a newly promoted local DB for a minute.
    # Return promptly on standby so the next tick can observe repmgr's decision.
    if recovery == 't':
        wait_health(f'http://{target}:9000/router/rest/health', seconds=8)
    state = read_pending(pending)
    pool_failures = root / '.pool-probe-failure.json'
    if state and state['phase'] == 'pool':
        writable_pool = False
    else:
        try:
            writable_pool = query('SELECT NOT pg_is_in_recovery()', pool=True) == 't'
        except RuntimeError:
            # A slow probe is not proof that the pool needs replacement.
            # Recreating it disconnects every client, which can then make the
            # API supervisor withdraw a healthy owner. Preserve the production
            # role-change repair, but require sustained failure in steady state.
            now = time.time()
            failures = json.loads(pool_failures.read_text()) if pool_failures.exists() else {}
            first = failures.get('first', now)
            if first > now:
                first, failures = now, {}
            failures = {'first': first, 'count': failures.get('count', 0) + 1}
            save_pending(pool_failures, failures)
            if failures['count'] < 3 or now - first < 15:
                raise RuntimeError('Pgpool probe timed out; defer replacement until sustained failure') from None
            writable_pool = False
        else:
            pool_failures.unlink(missing_ok=True)
    if (state and state['phase'] == 'pool') or not writable_pool:
        # Pgpool must rediscover the writable backend before clients reconnect.
        dbroot = Path(env['HA_DATABASE_ROOT'])
        run(['docker', 'compose', 'up', '-d', '--no-deps', '--pull', 'never',
             '--force-recreate', '--timeout', '2', 'pgpool'], cwd=dbroot)
        wait_database(expected_role=recovery)
        pool_failures.unlink(missing_ok=True)
        if state:
            state['phase'] = 'clients'
            save_pending(pending, state)
    if recovery == 'f':
        # Router and pool startup overlap after promotion. Both must be ready
        # before starting DataService, without serializing their warm-up time.
        wait_health(f'http://{target}:9000/router/rest/health', seconds=60)
    if stable_proxy:
        run(['/usr/local/sbin/certlocker-uncloud-router-proxy', 'select',
             '--company', company, '--target', target], timeout=15)
        if recovery == 't' and running:
            # Switch client sockets to the verified peer before removing a
            # returning node's old Router. The clients keep their JVMs running.
            run([*compose, 'stop', '-t', '2', 'router'], cwd=root)
            run([*compose, 'rm', '-f', 'router'], cwd=root)
        services = await_native_clients(local, target, company, expected_role=recovery)
        if not services:
            save_pending(healthy_receipt, {'version': 1, 'clients': client_processes()})
            pending.unlink(missing_ok=True)
            print(json.dumps({'database_role': role, 'router': target,
                              'repaired': [], 'native_reconnect': True}))
            return
        state = {'phase': 'clients', 'remaining': services.copy(),
                 'attempted': state.get('attempted', []) if state else []}
        save_pending(pending, state)
        # Losing a Router registry does not invalidate a healthy JVM. Retain
        # its process across timer retries, even when native reconnect is slow.
        # StartedAt distinguishes a survivor from the same container cold-
        # starting after a reboot; failed cold starts remain repairable below.
        if healthy_survivors(healthy_receipt, client_processes(), services):
            raise RuntimeError('Native registration pending; surviving Java processes preserved for the next tick')
    else:
        nodes = router_status(target, company)['nodes']
        services = list(state['remaining']) if state else repair_services(nodes, local)
    if services:
        # HTTP readiness can fail while the primary is shutting down even
        # though its old registry still reports ACTIVE clients. Recheck the
        # current election and pool before replacing any otherwise healthy JVM.
        wait_database(expected_role=recovery)
        # Record only exception class names and known failure counts before a
        # repair replaces the container. Never print application log messages.
        for service in services:
            try:
                diagnostic = subprocess.run(['docker', 'logs', '--since', '2m', '--tail', '1500',
                                             'certlocker-' + service], capture_output=True,
                                            text=True, timeout=3)
                output = diagnostic.stdout + diagnostic.stderr
                print(json.dumps({'stage': 'client-repair-diagnostic', 'service': service,
                                  'exception_types': sorted(set(re.findall(
                                      r'\b(?:[a-zA-Z_]\w*\.)+[A-Z]\w*(?:Exception|Error)\b', output))),
                                  'cache_load_failures': output.count('Unable to load cache for node')}),
                      flush=True)
            except subprocess.TimeoutExpired:
                pass
        if state is None:
            state = {'phase': 'clients', 'remaining': services.copy()}
            save_pending(pending, state)
        # DataService must register before its clients start. The remaining
        # clients can start concurrently, as in the original HA recovery path.
        if 'dataservice' in services:
            restart_wave(root, compose, ['dataservice'], local, target, pending, state)
        others = [service for service in services if service != 'dataservice']
        if others:
            restart_wave(root, compose, others, local, target, pending, state)
    remaining = repair_services(router_status(target, company)['nodes'], local)
    if remaining:
        save_pending(pending, {'phase': 'clients', 'remaining': remaining})
        raise RuntimeError('Local registrations not ACTIVE; next tick retries missing clients')
    pending.unlink(missing_ok=True)
    if stable_proxy:
        save_pending(healthy_receipt, {'version': 1, 'clients': client_processes()})
    print(json.dumps({'database_role': role, 'router': target, 'repaired': services}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--company', required=True)
    parser.add_argument('--local', required=True)
    parser.add_argument('--peer', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.company):
        raise ValueError('Invalid company')
    local, peer = str(ipaddress.ip_address(args.local)), str(ipaddress.ip_address(args.peer))
    with open('/run/certlocker-' + args.company + '-ha.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        reconcile(Path('/opt/certlocker') / args.company / 'uncloud-apps', local, peer)


if __name__ == '__main__':
    main()
