"""Readiness checks for two existing servers on a routed network."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import re
import secrets
import shlex

from uncloud_ssh import run_ssh

MESH = ipaddress.IPv4Network('10.210.0.0/16')

# Runs under the SSH user. Only the Docker inventory needs elevated privileges.
PROBE = """
import json, os, platform, shutil, socket, subprocess
from pathlib import Path
def output(*args):
    return subprocess.check_output(args, text=True)
subprocess.run(['sudo', '-n', 'true'], check=True)
release = platform.freedesktop_os_release()
marker = Path('/etc/certlocker-uncloud')
print(json.dumps(dict(
    hostname=socket.gethostname().split('.')[0],
    machine=Path('/etc/machine-id').read_text().strip(),
    os=release['ID'], version=release['VERSION_ID'], arch=platform.machine(),
    memory=int(Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),
    ssh=os.environ['SSH_CONNECTION'].split(),
    routes=json.loads(output('ip', '-j', '-4', 'route', 'show', 'table', 'all')),
    addresses=[a['local'] for i in json.loads(output('ip', '-j', '-4', 'address'))
               for a in i['addr_info']],
    sockets=output('ss', '-H', '-lntu'),
    containers=bool(output('sudo', '-n', 'docker', 'ps', '-aq').strip()) if shutil.which('docker') else False,
    marker=marker.read_text().strip() if marker.exists() else None)))
"""

# Both peers send throughout the window so either SSH command can start first.
UDP_PROBE = """
import socket, sys, time
local, peer, outgoing, incoming = sys.argv[1:]
received = False
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((local, 51820))
    sock.settimeout(0.25)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        sock.sendto(outgoing.encode(), (peer, 51820))
        try:
            packet, source = sock.recvfrom(128)
            received |= source == (peer, 51820) and packet == incoming.encode()
            time.sleep(0.1)
        except TimeoutError:
            pass
print('reachable' if received else 'unreachable')
"""


def check_peer_udp(names, hosts, key, user):
    tokens = {name: secrets.token_hex(16) for name in names}
    first, second = names
    errors = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        probes = []
        for name, peer in ((first, second), (second, first)):
            host = hosts[name]
            command = shlex.join(['python3', '-c', UDP_PROBE, host['uncloud_private_ip'],
                                  hosts[peer]['uncloud_private_ip'], tokens[name], tokens[peer]])
            result = pool.submit(run_ssh, key, host['ansible_host'], command, user=user, wait_seconds=22)
            probes.append((name, peer, result))
        for name, peer, result in probes:
            try:
                if result.result().strip() != 'reachable':
                    errors.append(f'{name}: no UDP/51820 traffic received from {peer}; check peer firewall and routing')
            except RuntimeError as error:
                errors.append(f'{name}: could not run the UDP/51820 probe: {error}')
    return errors


def listening_ports(fact):
    for line in fact['sockets'].splitlines():
        proto, _, _, _, local_socket, *_ = line.split()
        yield proto, local_socket.rsplit(':', 1)[-1]


def inspect_pair(names, addresses, nodes, key, user, *, operator_cidrs=(), bound=False):
    """Resolve management and underlay addresses independently and check both nodes."""
    facts, hosts, sources, errors = {}, {}, set(), []
    for name, address in zip(names, addresses):
        try:
            snapshot = run_ssh(key, address, shlex.join(['python3', '-c', PROBE]),
                               user=user, wait_seconds=12)
            fact = facts[name] = json.loads(snapshot)
            source, _, local, _ = fact['ssh']
            source = str(ipaddress.IPv4Address(source)) + '/32'
            sources.add(source)
            settings = nodes.get(name, {})
            peer = settings.get('wireguard_endpoint', local)
            peer = str(ipaddress.IPv4Address(peer))
            hostname = fact['hostname']
            hosts[name] = dict(ansible_host=address, uncloud_expected_hostname=hostname,
                               uncloud_provider='supplied', uncloud_private_ip=peer,
                               uncloud_machine_id=fact['machine'])
            print(f"{name}: {hostname}, SSH {address} from {source}, "
                  f"{fact['os']} {fact['version']}, {fact['memory'] / 1048576:.1f} GiB RAM", flush=True)
            issues = []
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', hostname) or hostname != settings.get('expected_hostname', hostname):
                issues.append('SSH hostname differs from the configured hostname')
            if not fact['machine'] or (fact['os'], fact['version'], fact['arch']) != ('ubuntu', '24.04', 'x86_64'):
                issues.append('requires an identifiable Ubuntu 24.04 amd64 server')
            if peer not in fact['addresses'] or ipaddress.IPv4Address(peer).is_loopback:
                issues.append('WireGuard endpoint must be an IPv4 address on this server')
            if operator_cidrs and source not in operator_cidrs:
                issues.append('operator_cidrs must include the observed SSH source ' + source)
            marker = fact['marker']
            if marker is not None and not (bound and marker == name):
                issues.append('server already has an enrollment outside this installation binding')
            if marker is None:
                if fact['containers']:
                    issues.append('server already has Docker workloads')
                for proto, port in listening_ports(fact):
                    if (proto, port) in {('tcp', '80'), ('tcp', '443'), ('udp', '51820')}:
                        issues.append('port already in use: ' + proto + '/' + port)
                if any(MESH.overlaps(ipaddress.IPv4Network(route['dst'], strict=False))
                       for route in fact['routes'] if route.get('dst') not in (None, 'default', '0.0.0.0/0')):
                    issues.append('existing route overlaps the CertLocker mesh ' + str(MESH))
            errors.extend(name + ': ' + issue for issue in issues)
        except (RuntimeError, ValueError, KeyError) as error:
            errors.append(name + ': ' + str(error))

    if len(hosts) == 2:
        first, second = names
        initial = {name: hosts[name]['uncloud_private_ip'] for name in names}
        for name, other in ((first, second), (second, first)):
            if 'wireguard_endpoint' in nodes.get(name, {}):
                continue
            try:
                route = run_ssh(key, hosts[name]['ansible_host'], 'ip -j -4 route get ' + initial[other],
                                user=user, wait_seconds=12)
                routes = json.loads(route)
                if len(routes) != 1 or routes[0].get('prefsrc') not in facts[name]['addresses']:
                    raise ValueError('could not detect a local peer address as source')
                endpoint = ipaddress.IPv4Address(routes[0]['prefsrc'])
                if endpoint.is_loopback:
                    raise ValueError('peer route selected a loopback address')
                hosts[name]['uncloud_private_ip'] = str(endpoint)
            except (RuntimeError, ValueError, KeyError) as error:
                errors.append(name + ': ' + str(error))
        if (facts[first]['machine'] == facts[second]['machine'] or
                hosts[first]['uncloud_private_ip'] == hosts[second]['uncloud_private_ip']):
            errors.append('SSH addresses must reach distinct machines with distinct WireGuard endpoints')
        for name, other in ((first, second), (second, first)):
            print(f"{name}: selected peer IPv4 {hosts[name]['uncloud_private_ip']}", flush=True)
            neighbor = hosts[other]['uncloud_private_ip']
            try:
                raw = run_ssh(key, hosts[name]['ansible_host'], 'ip -j -4 route get ' + neighbor,
                              user=user, wait_seconds=12)
                routes = json.loads(raw)
                if len(routes) != 1 or routes[0].get('prefsrc') != hosts[name]['uncloud_private_ip']:
                    errors.append(f'{name}: route to {neighbor} must use the configured local WireGuard endpoint as source')
            except (RuntimeError, ValueError) as error:
                errors.append(name + ': ' + str(error))
        if not errors:
            if any(('udp', '51820') in listening_ports(facts[name]) for name in names):
                print('UDP/51820 is already in use on an enrolled host. Use --verify-only to check the installed mesh.',
                      flush=True)
            else:
                errors.extend(check_peer_udp(names, hosts, key, user))
    if errors:
        raise ValueError('\n'.join(errors))
    return hosts, sorted(sources)
