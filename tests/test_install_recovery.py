"""Regression coverage for first-boot SSH and verified installation recording."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import uncloud_ssh as ssh
import uncloud_install_receipt as receipt
from uncloud_support import discover_host_trust_names


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class SSHRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        for name in ('monotonic', 'sleep'):
            p = patch.object(ssh.time, name, getattr(self.clock, name))
            p.start()
            self.addCleanup(p.stop)

    def test_first_boot_can_take_more_than_eighteen_fast_rejections(self):
        denied = Mock(returncode=255, stderr='Permission denied (publickey)', stdout='')
        ready = Mock(returncode=0, stdout='')
        with patch.object(ssh.subprocess, 'run', side_effect=[denied] * 30 + [ready]) as run, \
                redirect_stdout(io.StringIO()) as output:
            ssh.wait_for_ssh('/dev/shm/example-key', '8.8.8.8')
        self.assertEqual(run.call_count, 31)
        self.assertEqual(self.clock.now, 150)
        args = run.call_args.args[0]
        for option in ('IdentitiesOnly=yes', 'IdentityAgent=none', 'BatchMode=yes', 'ControlPath=none'):
            self.assertIn(option, args)
        self.assertIn('/dev/shm/example-key', args)
        self.assertIn('sudo -n true', args)
        self.assertIn('server rejected', output.getvalue())
        self.assertNotIn('/dev/shm/example-key', output.getvalue())

    def test_sudo_readiness_is_retried_without_replaying_other_remote_commands(self):
        sudo = Mock(returncode=1, stderr='sudo: a password is required', stdout='')
        with patch.object(ssh.subprocess, 'run', side_effect=[sudo, Mock(returncode=0, stdout='')]) as run:
            ssh.wait_for_ssh('/key', '8.8.8.8')
            self.assertEqual(run.call_count, 2)
        with patch.object(ssh.subprocess, 'run', return_value=sudo) as run:
            with self.assertRaisesRegex(RuntimeError, 'passwordless sudo'):
                ssh.run_ssh('/key', '8.8.8.8', 'read-only-probe')
            run.assert_called_once()

    def test_deadline_reports_reason_without_echoing_remote_output(self):
        stderr = 'Permission denied (publickey) sensitive-remote-value'
        with patch.object(ssh.subprocess, 'run', return_value=Mock(returncode=255, stderr=stderr)), \
                redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(RuntimeError, 'deadline.*10s') as caught:
                ssh.run_ssh('/key', '8.8.8.8', 'probe', wait_seconds=10)
        self.assertEqual(self.clock.now, 10)
        self.assertNotIn('sensitive-remote-value', str(caught.exception) + output.getvalue())
        self.assertIn('provisioning key', str(caught.exception))

    def test_host_key_change_fails_immediately_and_never_removes_trust(self):
        with patch.object(ssh.subprocess, 'run', return_value=Mock(returncode=255,
                stderr='REMOTE HOST IDENTIFICATION HAS CHANGED')) as run:
            with self.assertRaisesRegex(RuntimeError, 'Host key verification failed'):
                ssh.wait_for_ssh('/key', '8.8.8.8')
        run.assert_called_once()
        self.assertEqual(self.clock.now, 0)

    def test_hung_ssh_has_a_process_timeout_and_bounded_retry(self):
        def timeout(*args, **kwargs):
            self.clock.now += kwargs['timeout']
            raise subprocess.TimeoutExpired(args[0], kwargs['timeout'])
        with patch.object(ssh.subprocess, 'run', side_effect=timeout) as run:
            with self.assertRaisesRegex(RuntimeError, 'firewall source /32'):
                ssh.run_ssh('/key', '8.8.8.8', 'probe', wait_seconds=12)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(self.clock.now, 12)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {'company': 'example', 'ssh_private_key': '/logical-key',
                       'ssh_user': 'ucdeploy', 'trust_group': 'Example'}
        self.cycle = {'status': 'passed', 'verified_through': 'apps', 'install_passed': True,
                      'verify_passed': True, 'public_database_closed': True, 'generation': 'generation-a',
                      'state_dir': str(self.root), 'final_release': {'release': 'prod_1.1.28'},
                      'nodes': {name: {'public_ip': address, 'private_ip': '10.0.0.' + str(index + 1),
                                      'reported_public_ip': '8.8.8.' + str(index + 1)}
                                for index, (name, address) in enumerate([
                                    ('example-a', '192.0.2.10'), ('example-b', '192.0.2.20')])}}
        self.company_file = self.root / 'company.json'
        self.install_file = self.root / 'install.json'
        self.company_file.write_text(json.dumps(self.config, indent=2) + '\n')
        self.install_file.write_text('{"hosting": {"provider": "google"}}\n')
        customer = patch.object(receipt, 'archive_customer_installation', return_value={
            'status': 'saved', 'record_id': 'customer-id', 'record_name': 'example installer JSON'})
        self.customer_archive = customer.start()
        self.addCleanup(customer.stop)
        self.records = {}
        self.trust = Mock()
        def ensure(name, company, factory):
            return self.records.setdefault(name, factory())
        self.trust.ensure_named.side_effect = ensure
        self.trust.get.side_effect = lambda name: self.records.get(name)

    def archive(self):
        return receipt.archive_installation('example', self.config, self.cycle, self.company_file, self.install_file)

    def test_public_addresses_are_observed_on_both_nodes_over_pinned_ssh(self):
        with patch.object(receipt, 'runtime_ssh_key', return_value=Path('/dev/shm/identity')), \
                patch.object(receipt, 'run_ssh', side_effect=['1.1.1.1\n', '8.8.8.8\n']) as run:
            observed = receipt.collect_public_ips(self.config, self.cycle)
        self.assertEqual(observed, {'example-a': '1.1.1.1', 'example-b': '8.8.8.8'})
        self.assertEqual([call.args[1] for call in run.call_args_list], ['192.0.2.10', '192.0.2.20'])
        for call in run.call_args_list:
            self.assertIn('curl ', call.args[2])
            self.assertIn('https://ifconfig.me/ip', call.args[2])
            self.assertEqual(call.kwargs['known_hosts'], self.root / 'known_hosts')
        self.assertEqual(self.cycle['nodes']['example-a']['public_ip'], '192.0.2.10')
        self.assertEqual(self.cycle['nodes']['example-a']['reported_public_ip'], '1.1.1.1')

    def test_ip_lookup_rejects_html_private_addresses_and_failures(self):
        for value in ('<html>error</html>', '10.0.0.1', '1.1.1.1\n8.8.8.8', ''):
            with self.subTest(value=value), patch.object(receipt, 'run_ssh', return_value=value):
                with self.assertRaisesRegex(RuntimeError, 'no installation success notification'):
                    receipt.collect_public_ips(self.config, self.cycle)
        with patch.object(receipt, 'run_ssh', side_effect=RuntimeError('private output')):
            with self.assertRaises(RuntimeError) as caught:
                receipt.collect_public_ips(self.config, self.cycle)
            self.assertNotIn('private output', str(caught.exception))

    def test_archive_keeps_exact_json_and_checks_remote_readback(self):
        with patch.object(receipt, 'Trust', return_value=self.trust):
            result = self.archive()
            self.assertEqual(self.archive(), result)
        self.assertEqual(len(self.records), 1)
        document = self.records[result['installation_record']]
        self.assertEqual(document['files']['company.json'], self.company_file.read_text())
        self.assertEqual(document['files']['install.json'], self.install_file.read_text())
        self.assertEqual(document['nodes'], self.cycle['nodes'])
        self.trust.get.assert_called_with(result['installation_record'])
        local = self.root / 'installation-trust.json'
        self.assertEqual(local.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('/logical-key', local.read_text())
        self.assertIn(result['installation_record'], discover_host_trust_names('example', self.root))

    def test_operator_copy_is_pinned_and_both_destinations_are_verified(self):
        with patch.dict(os.environ, {'CERTLOCKER_API_URL': 'https://customer.example.com/rest'}), \
                patch.object(receipt, 'Trust', return_value=self.trust) as factory:
            result = self.archive()
        self.assertEqual(factory.call_args.kwargs['api_url'], 'https://trust.certlocker.io/rest')
        self.assertEqual(result['operator']['status'], 'saved')
        self.assertEqual(result['customer']['status'], 'saved')
        self.assertEqual(self.customer_archive.call_args.args[3], self.records[result['installation_record']])

    def test_customer_failure_preserves_operator_receipt_for_resume(self):
        self.customer_archive.side_effect = RuntimeError('Customer archive unavailable')
        with patch.object(receipt, 'Trust', return_value=self.trust):
            with self.assertRaisesRegex(RuntimeError, 'Customer archive unavailable'):
                self.archive()
            marker = json.loads((self.root / 'installation-trust.json').read_text())
            self.assertEqual(marker['status'], 'operator_saved')
            self.assertEqual(marker['customer']['status'], 'pending')
            self.customer_archive.side_effect = None
            self.assertEqual(self.archive()['status'], 'saved')
        self.assertEqual(len(self.records), 1)

    def test_missing_readback_does_not_mark_archive_saved(self):
        self.trust.get.side_effect = lambda name: None
        with patch.object(receipt, 'Trust', return_value=self.trust):
            with self.assertRaisesRegex(RuntimeError, 'read-back'):
                self.archive()
        self.assertFalse((self.root / 'installation-trust.json').exists())

    def test_failed_or_partial_installation_never_writes_archive_or_probes_nodes(self):
        with patch.dict(self.cycle, {'verify_passed': False}), \
                patch.object(receipt, 'Trust') as trust, patch.object(receipt, 'run_ssh') as run:
            with self.assertRaises(ValueError):
                self.archive()
            with self.assertRaises(ValueError):
                receipt.collect_public_ips(self.config, self.cycle)
        trust.assert_not_called()
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
