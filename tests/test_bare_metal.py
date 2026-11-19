import json
from pathlib import Path
import shlex
import sys
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import controller_runtime
from uncloud_bare_metal import UDP_PROBE, inspect_pair


class BareMetalReadiness(unittest.TestCase):
    names = ('example-a', 'example-b')
    addresses = ('192.0.2.11', '192.0.2.12')
    peers = ('10.30.0.11', '10.30.0.12')

    def setUp(self):
        self.facts = {}
        self.route_sources = dict(zip(self.addresses, self.peers))
        self.udp_status = dict.fromkeys(self.addresses, 'reachable')
        for name, address, peer in zip(self.names, self.addresses, self.peers):
            self.facts[address] = dict(
                hostname=name, machine=name, os='ubuntu', version='24.04', arch='x86_64',
                ssh=['10.40.0.2', '50000', peer, '22'], memory=8*1024*1024,
                addresses=[peer], routes=[{'dst': 'default'}, {'dst': '10.30.0.0/24'}],
                containers=False, marker=None, sockets='tcp LISTEN 0 100 0.0.0.0:22 0.0.0.0:*')

    def run_probe(self, *, nodes=None, **kwargs):
        def ssh(key, address, command, **options):
            if command.startswith('ip -j'):
                return json.dumps([{'prefsrc': self.route_sources[address]}])
            if shlex.split(command)[2] == UDP_PROBE:
                return self.udp_status[address]
            return json.dumps(self.facts[address])

        with patch('uncloud_bare_metal.run_ssh', side_effect=ssh):
            return inspect_pair(self.names, self.addresses, nodes or {}, 'fixture', 'ubuntu', **kwargs)

    def test_management_and_tunnel_use_separate_addresses(self):
        hosts, sources = self.run_probe()
        self.assertEqual(hosts['example-b']['ansible_host'], self.addresses[1])
        self.assertEqual(hosts['example-b']['uncloud_private_ip'], self.peers[1])
        self.assertEqual(sources, ['10.40.0.2/32'])

    def test_automatic_peer_uses_the_route_source_on_multihomed_servers(self):
        alternate = '10.30.0.21'
        self.facts[self.addresses[0]]['addresses'].append(alternate)
        self.route_sources[self.addresses[0]] = alternate
        hosts, _ = self.run_probe()
        self.assertEqual(hosts[self.names[0]]['uncloud_private_ip'], alternate)

    def test_same_node_under_two_management_addresses_is_rejected(self):
        self.facts[self.addresses[1]]['machine'] = self.names[0]
        with self.assertRaisesRegex(ValueError, 'distinct machines'):
            self.run_probe()

    def test_four_gib_hosts_pass_readiness(self):
        for fact in self.facts.values():
            fact['memory'] = 4 * 1024 * 1024
        hosts, _ = self.run_probe()
        self.assertEqual(set(hosts), set(self.names))

    def test_existing_native_listener_and_overlapping_route_are_reported_together(self):
        first = self.facts[self.addresses[0]]
        first['sockets'] += '\ntcp LISTEN 0 100 [::]:443 [::]:*'
        first['routes'].append({'dst': '10.210.44.0/24'})
        with self.assertRaises(ValueError) as failure:
            self.run_probe()
        for message in ('tcp/443', 'overlaps'):
            self.assertIn(message, str(failure.exception))

    def test_peer_must_be_local_and_match_selected_source(self):
        self.route_sources[self.addresses[1]] = '10.99.0.12'
        with self.assertRaises(ValueError) as failure:
            self.run_probe(nodes={'example-a': {'wireguard_endpoint': '10.99.0.11'}})
        self.assertIn('on this server', str(failure.exception))
        self.assertIn('as source', str(failure.exception))

    def test_wrong_ssh_source_cannot_lock_out_controller(self):
        with self.assertRaisesRegex(ValueError, 'observed SSH source'):
            self.run_probe(operator_cidrs=['10.40.0.9/32'])

    def test_route_without_udp_in_both_directions_fails_readiness(self):
        self.udp_status[self.addresses[0]] = 'unreachable'
        with self.assertRaisesRegex(ValueError, 'example-a: no UDP/51820 traffic received from example-b'):
            self.run_probe()

    def test_existing_enrollment_requires_the_matching_binding(self):
        first = self.facts[self.addresses[0]]
        first.update(marker='example-a', containers=True)
        with self.assertRaisesRegex(ValueError, 'outside this installation'):
            self.run_probe()
        self.run_probe(bound=True)
        first['marker'] = 'another-a'
        with self.assertRaisesRegex(ValueError, 'outside this installation'):
            self.run_probe(bound=True)

    def test_container_install_skips_workstation_google_login(self):
        with patch.dict('os.environ', CERTLOCKER_USE_CONTROLLER='1'), \
                patch.object(controller_runtime, 'docker_command', return_value=['docker']), \
                patch.object(controller_runtime, 'ensure_image', return_value='controller'), \
                patch.object(controller_runtime, 'workstation_google_login') as login, \
                patch.object(controller_runtime, 'container_arguments', return_value=['run']) as arguments, \
                patch.object(controller_runtime, 'command'):
            controller_runtime.main(['uncloud', 'bare-metal', 'example', *self.addresses])
        login.assert_not_called()
        arguments.assert_called_once_with('setup-ha', ['--bare-metal', 'example', *self.addresses], 'controller', None)
