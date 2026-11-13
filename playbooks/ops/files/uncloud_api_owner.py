#!/usr/bin/env python3
"""Own the Edge/Backoffice pair outside Java; fail closed without two-node DB agreement.

PostgreSQL serializes leases. An expiring kernel packet gate prevents a paused
supervisor from serving beyond its lease. Standby loss may continue on the last
jointly verified writer. After that writer's VM stays unreachable long enough for
old leases to expire, a locally promoted writable database that was previously
the verified standby may assume lease authority. Network partitions without an
independent witness remain unsafe; this is not a quorum/fencing service.
"""
import argparse
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import selectors
import socket
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APIS = {'edge': (8500, 'edge', 'EDGE'), 'backoffice-api': (8600, 'backoffice', 'BACKOFFICE')}
LEASE_SECONDS = 30
GATE_SECONDS = 8
PROBE_MARK = 0x434C
# Wait out every previously issued lease and packet gate before a promoted
# standby may become the lease authority while the old writer stays unreachable.
PROMOTE_ASSUME_SECONDS = LEASE_SECONDS + GATE_SECONDS + 5
# A small VM can still be scanning classes after 45 seconds. Keep the gate
# withdrawn from browser traffic while allowing a bounded cold JVM startup.
START_STAGE_SECONDS = 120
START_TOTAL_SECONDS = 480
DDL = """CREATE SCHEMA IF NOT EXISTS certlocker_ha;
CREATE TABLE IF NOT EXISTS certlocker_ha.api_owner (
 id integer PRIMARY KEY CHECK (id=1), owner text NOT NULL, incarnation text NOT NULL,
 expires timestamptz NOT NULL, preferred text NOT NULL);
"""


def run(argv, *, data=None, timeout=10, cwd=None):
    try:
        p = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Ownership operation timed out: ' + argv[0]) from None
    if p.returncode:
        raise RuntimeError('Ownership operation failed: ' + argv[0] + '; private output suppressed')
    return p.stdout.strip()


def connection_args(host):
    # Credentials stay inside the existing database container; SQL goes via stdin.
    return ['docker', 'exec', '-i', 'certlocker-uncloud-postgres', 'bash', '-ec',
                'export PGPASSWORD="$(cat /run/lab-secrets/postgres)" PGSSLMODE=require PGCONNECT_TIMEOUT=2; '
                'export PGOPTIONS="-c statement_timeout=2000 -c lock_timeout=1500"; '
                'exec psql -X -qAt -h "$1" -U postgres -d certlocker -v ON_ERROR_STOP=1', 'query', host]


class SQLConnection:
    """Reuse a psql session instead of spawning runc for every lease heartbeat."""
    def __init__(self, host):
        self.host = host
        self.process = None

    def close(self):
        p, self.process = self.process, None
        if p is not None:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=3)
            p.stdin.close()
            p.stdout.close()

    def query(self, statement, timeout=5):
        try:
            if self.process is None or self.process.poll() is not None:
                self.close()
                self.process = subprocess.Popen(connection_args(self.host), stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            marker = ('cl_query_' + uuid.uuid4().hex).encode()
            self.process.stdin.write(statement.encode() + b'\n\\echo ' + marker + b'\n')
            self.process.stdin.flush()
            deadline, data = time.monotonic() + timeout, b''
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    if not selector.select(max(0, deadline - time.monotonic())):
                        break
                    chunk = os.read(self.process.stdout.fileno(), 65536)
                    if not chunk:
                        raise RuntimeError('Database session ended before query completion')
                    data += chunk
                    if data.endswith(marker + b'\n'):
                        return data[:-len(marker)-1].decode().strip()
                    if len(data) > 65536:
                        raise RuntimeError('Unexpected ownership query response size')
            raise RuntimeError('Ownership database query timed out')
        except Exception:
            self.close()
            raise RuntimeError('Ownership database session failed; private output suppressed') from None


CONNECTIONS = {}


def sql(host, statement, timeout=5):
    return CONNECTIONS.setdefault(host, SQLConnection(host)).query(statement, timeout=timeout)


def topology(local, peer, continuation=None, assume_after=None):
    """Return (primary, identity, peer_reachable)."""
    results = {}
    failures = []
    for host in (local, peer):
        try:
            row = sql(host, "SELECT json_build_object('standby',pg_is_in_recovery(),"
                           "'boot',pg_postmaster_start_time()::text);",
                      timeout=1 if continuation and host != continuation[0] else 5)
            results[host] = json.loads(row)
        except RuntimeError as error:
            failures.append(error)
    peer_reachable = peer in results
    if failures:
        # The last jointly verified writer remains the lease authority while
        # the standby reboots. Its unchanged postmaster epoch is mandatory.
        if continuation:
            primary, identity = continuation
            row = results.get(primary)
            if row and row['standby'] is False and primary + '/' + row['boot'] == identity:
                return primary, identity, peer_reachable
            # Previous writer unreachable: a locally promoted former standby may
            # assume authority only after old leases/gates have expired.
            local_row = results.get(local)
            if (assume_after is not None and time.monotonic() >= assume_after and
                    primary == peer and peer not in results and local_row and
                    local_row['standby'] is False):
                return local, local + '/' + local_row['boot'], False
        raise failures[0]
    if sorted(row['standby'] for row in results.values()) != [False, True]:
        raise RuntimeError('Single writable database not confirmed on both nodes')
    primary = next(host for host, row in results.items() if not row['standby'])
    return primary, primary + '/' + results[primary]['boot'], True


def lease_statement(local, incarnation, preferred):
    # All substitutions validated IPs, UUID and integer constants, never user SQL.
    return f"""INSERT INTO certlocker_ha.api_owner VALUES
    (1,'{local}','{incarnation}',clock_timestamp()+interval '{LEASE_SECONDS} seconds','{preferred}')
    ON CONFLICT (id) DO UPDATE SET owner=EXCLUDED.owner, incarnation=EXCLUDED.incarnation,
      expires=EXCLUDED.expires
    WHERE (api_owner.owner='{local}' AND api_owner.incarnation='{incarnation}')
       OR (api_owner.expires < clock_timestamp() AND
           (api_owner.preferred='{local}' OR api_owner.expires < clock_timestamp()-interval '10 seconds'))
    RETURNING owner;
    """


class KernelGate:
    def __init__(self, company):
        self.table = 'cl_owner_' + company.replace('-', '_')

    def install(self):
        # An empty set blocks ordinary traffic, including established connections.
        # Only this root supervisor's marked readiness probes bypass the gate.
        exists = subprocess.run(['nft', 'list', 'table', 'inet', self.table], capture_output=True).returncode == 0
        if exists:
            self.close()
            return
        run(['nft', '-f', '-'], data=f'''table inet {self.table} {{
 set serving {{ type inet_service; flags timeout; timeout {GATE_SECONDS}s; }}
 chain guard {{ type filter hook input priority -20; policy accept;
   tcp dport {{ 8500, 8600 }} meta mark != {PROBE_MARK} tcp dport != @serving reject with tcp reset
 }}
}}
''')

    def close(self):
        run(['nft', 'flush', 'set', 'inet', self.table, 'serving'], timeout=3)

    def open(self, remaining):
        if remaining < GATE_SECONDS + 2:
            raise RuntimeError('Lease too short to open the application gate')
        # Replace in one nft transaction, without a momentary gap.
        run(['nft', '-f', '-'], timeout=3, data=f'''flush set inet {self.table} serving
add element inet {self.table} serving {{ 8500 timeout {GATE_SECONDS}s, 8600 timeout {GATE_SECONDS}s }}
''')


INTERNAL_SERVICE_HEADER = 'X-CL-Internal-Service-Key'


def internal_service_headers(company):
    key = (Path('/run/certlocker') / company / 'internal-service-key').read_text().strip()
    if len(key) < 32:
        raise RuntimeError('Internal service authentication key is unavailable')
    return {INTERNAL_SERVICE_HEADER: key}


def get(host, port, path, marked=False, json_body=True, headers=None):
    c = http.client.HTTPConnection(host, port, timeout=2)
    try:
        if marked:
            c.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.sock.settimeout(2)
            c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, PROBE_MARK)
            c.sock.connect((host, port))
        c.request('GET', path, headers=headers or {})
        r = c.getresponse()
        if r.status != 200:
            raise RuntimeError('Readiness HTTP status is not 200')
        body = r.read()
        return json.loads(body) if json_body else body
    finally:
        c.close()


class Owner:
    def __init__(self, company, local, peer, preferred):
        self.company, self.local, self.peer, self.preferred = company, local, peer, preferred
        self.root = Path('/opt/certlocker') / company / 'uncloud-apps'
        self.incarnation = str(uuid.uuid4())
        self.gate = KernelGate(company)
        self.deadline = 0.0
        self.starting = None
        self.serving = False
        self.has_served = False
        self.failures = 0
        self.primary = None
        self.identity = None
        self.settle_until = 0.0
        self.cooldown = 0.0
        self.stop_event = threading.Event()
        self.status = 'standby'
        self.last_gate = 0.0
        self.started_apis = set()
        self.stage_started = 0.0
        self.start_attempts = {}
        self.health_failure = None
        self.operation = 'initializing'
        self.peer_down_since = None
        self.peer_unreachable = False

    def compose(self, *args):
        return run(['docker', 'compose', '--profile', 'owned-api', *args], cwd=self.root, timeout=15)

    def stop(self):
        self.serving = False
        self.has_served = False
        self.last_gate = 0
        self.status = 'stopping'
        self.gate.close()
        # Closed kernel gate remains in place even if Docker cannot stop.
        self.compose('stop', '-t', '3', *APIS)
        self.starting = None
        self.started_apis.clear()
        self.start_attempts.clear()
        self.status = 'standby'

    def release(self, handoff_peer=True):
        # Never prefer a peer that is currently unreachable: that creates an
        # ownerless window and later ping-pong when the peer rejoins.
        preferred = self.peer if handoff_peer and not self.peer_unreachable else self.local
        if self.primary:
            sql(self.primary, f"UPDATE certlocker_ha.api_owner SET expires=clock_timestamp(),preferred='{preferred}' "
                              f"WHERE id=1 AND owner='{self.local}' AND incarnation='{self.incarnation}';")
        self.deadline = 0
        self.cooldown = time.monotonic() + (5 if self.peer_unreachable else 25)

    def readiness(self):
        self.health_failure = None
        active = {'EDGE', 'BACKOFFICE'}
        if not self.has_served:
            nodes = get('127.0.0.1', 19000, '/router/rest/status',
                        headers=internal_service_headers(self.company))['nodes']
            active = {row.get('type') for row in nodes
                      if row.get('host') == self.local and row.get('status') == 'ACTIVE'}
        for port, context, kind in APIS.values():
            if kind not in active:
                self.health_failure = kind + ':registration'
                return False
            try:
                healthy = get(self.local, port, f'/{context}/rest/health', marked=True).get('success') is True
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                self.health_failure = kind + ':' + type(error).__name__
                return False
            if not healthy:
                self.health_failure = kind + ':health'
                return False
        for port in (3080, 3081):
            try:
                get(self.local, port, '/', json_body=False)
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                self.health_failure = 'ui-' + str(port) + ':' + type(error).__name__
                return False
        return True

    def api_ready(self, service):
        port, context, kind = APIS[service]
        try:
            nodes = get('127.0.0.1', 19000, '/router/rest/status',
                        headers=internal_service_headers(self.company))['nodes']
            return (any(n.get('host') == self.local and n.get('type') == kind and n.get('status') == 'ACTIVE' for n in nodes)
                    and get(self.local, port, f'/{context}/rest/health', marked=True).get('success') is True)
        except (OSError, ValueError, RuntimeError, KeyError):
            return False

    def start_next(self):
        """Start the owned pair together, retrying a stalled registration once."""
        if not self.started_apis:
            self.compose('up', '-d', '--no-deps', '--pull', 'never', *APIS)
            self.started_apis.update(APIS)
            self.start_attempts = {service: 1 for service in APIS}
            self.stage_started = time.monotonic()
            return
        for service in APIS:
            if not self.api_ready(service):
                if time.monotonic() - self.stage_started > START_STAGE_SECONDS:
                    if self.start_attempts[service] >= 2:
                        self.stop()
                        self.release()
                        return
                    # A fresh JVM is enough to reload caches. Recreating the
                    # container can outlive the command deadline on a small VM
                    # and leave Compose halfway through a replacement.
                    self.compose('restart', '-t', '3', service)
                    self.start_attempts[service] += 1
                    self.stage_started = time.monotonic()
                return

    def tick(self):
        now = time.monotonic()
        self.operation = 'database-topology'
        continuation = ((self.primary, self.identity) if self.primary and self.identity else None)
        assume_after = None
        if continuation and continuation[0] == self.peer and self.peer_down_since is not None:
            assume_after = self.peer_down_since + PROMOTE_ASSUME_SECONDS
        try:
            primary, identity, peer_reachable = topology(
                self.local, self.peer, continuation, assume_after=assume_after)
            self.peer_unreachable = not peer_reachable
            if peer_reachable:
                self.peer_down_since = None
            elif continuation and continuation[0] == self.peer:
                if self.peer_down_since is None:
                    self.peer_down_since = now
            # Surviving writer with unreachable standby: keep sole-survivor mode.
        except RuntimeError:
            self.peer_unreachable = True
            if continuation and continuation[0] == self.peer:
                if self.peer_down_since is None:
                    self.peer_down_since = now
            else:
                self.peer_down_since = None
            raise
        if identity != self.identity:
            previous_writer = self.primary
            self.stop()
            self.primary, self.identity = primary, identity
            # Outlast all previously issued leases and packet gates on a changed
            # primary (including restart). Never trust an asynchronously copied lease.
            # When the old writer stayed unreachable long enough to expire its
            # leases, the promote-assume path already waited; settle only briefly.
            if previous_writer == self.peer and primary == self.local and assume_after is not None:
                self.settle_until = now + GATE_SECONDS + 2
            else:
                self.settle_until = now + LEASE_SECONDS + 5
            self.deadline = 0
        if now < max(self.settle_until, self.cooldown) or (self.root / '.api-owner-maintenance').exists():
            if self.starting is not None or self.serving:
                self.stop()
                self.release()
            return
        before = time.monotonic()
        self.operation = 'lease'
        acquired = sql(primary, lease_statement(self.local, self.incarnation, self.preferred)) == self.local
        if not acquired:
            if self.starting is not None or self.serving:
                self.stop()
            self.deadline = 0
            return
        self.deadline = before + LEASE_SECONDS
        # The elected process must answer Router registration/health callbacks
        # while warming up. Browser routing remains closed at port 8510 until
        # both APIs have loaded caches and registered ACTIVE.
        self.operation = 'packet-gate'
        self.gate.open(self.deadline - time.monotonic())
        self.last_gate = time.monotonic()
        if self.starting is None:
            self.status = 'starting'
            self.starting = time.monotonic()
        if not self.has_served:
            self.start_next()
            if self.starting is None:
                return
        try:
            self.operation = 'readiness'
            ready = len(self.started_apis) == len(APIS) and self.readiness()
        except (OSError, ValueError, RuntimeError, KeyError):
            ready = False
        if ready:
            self.gate.open(self.deadline - time.monotonic())
            self.last_gate = time.monotonic()
            self.serving, self.status, self.failures = True, 'serving', 0
            self.has_served = True
        else:
            self.serving = False
            self.status = 'starting' if not self.has_served else 'unhealthy'
            self.failures += 1
            # While the peer is down there is nobody to hand off to. Keep the
            # lease preference local and tolerate brief readiness blips.
            failure_limit = 8 if self.peer_unreachable else 2
            if (self.has_served and self.failures >= failure_limit) or time.monotonic() - self.starting > START_TOTAL_SECONDS:
                self.stop()
                self.release()

    def serve(self):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                valid = (owner.serving and time.monotonic() - owner.last_gate < GATE_SECONDS - 1
                         and owner.deadline - time.monotonic() > GATE_SECONDS + 2)
                body = json.dumps({'success': valid, 'state': owner.status}).encode()
                self.send_response(200 if valid else 503)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer((self.local, 8510), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.gate.install()
        self.stop()
        try:
            while not self.stop_event.is_set():
                tick_started = time.monotonic()
                try:
                    self.tick()
                    print(json.dumps({'state': self.status, 'owned_apis': sorted(self.started_apis),
                                      'serving': self.serving, 'health_failure': self.health_failure,
                                      'tick_seconds': round(time.monotonic() - tick_started, 3)}), flush=True)
                except Exception as error:
                    # Class only: SQL/HTTP/command outputs can contain secrets.
                    print(json.dumps({'state': 'blocked', 'error_type': type(error).__name__,
                                      'operation': self.operation,
                                      'tick_seconds': round(time.monotonic() - tick_started, 3)}), flush=True)
                    self.stop()
                    self.deadline = 0
                self.stop_event.wait(2)
        finally:
            self.stop()
            self.release()
            server.shutdown()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['run', 'stop', 'initialize'])
    p.add_argument('--company', required=True)
    p.add_argument('--local', required=True)
    p.add_argument('--peer', required=True)
    p.add_argument('--preferred', required=True)
    args = p.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', args.company):
        raise ValueError('Invalid company name')
    local, peer, preferred = (str(ipaddress.IPv4Address(x)) for x in (args.local, args.peer, args.preferred))
    if local == peer or preferred not in (local, peer):
        raise ValueError('Invalid owner mesh pair')
    owner = Owner(args.company, local, peer, preferred)
    if args.action == 'initialize':
        try:
            primary, _, _ = topology(local, peer)
            sql(primary, DDL)
        finally:
            for connection in CONNECTIONS.values():
                connection.close()
        return
    if args.action == 'stop':
        owner.gate.install()
        owner.stop()
        return
    with open('/run/certlocker-' + args.company + '-api-owner.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: owner.stop_event.set())
        try:
            owner.serve()
        finally:
            for connection in CONNECTIONS.values():
                connection.close()


if __name__ == '__main__':
    main()
