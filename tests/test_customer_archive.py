import base64
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import uncloud_customer_archive as archive
from uncloud_support import trust_name


class CustomerArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {'initial_admin_email': 'admin@example.com', 'account_domain': 'example.com',
                       'front_url': 'https://customer.example.com'}
        self.cycle = {'state_dir': str(self.root), 'nodes': {
            'example-a': {'public_ip': '192.0.2.10'}, 'example-b': {'public_ip': '192.0.2.20'}}}
        (self.root / '.setup.json').write_text(json.dumps({'company': 'example',
            'state_dir': str(self.root), 'addresses': ['192.0.2.10', '192.0.2.20'],
            'ssh_key_path': '/logical-key', 'ssh_user': 'ucdeploy'}))
        # Loader targets the first inventory host, which need not sort first.
        (self.root / 'hosts.json').write_text(json.dumps({'all': {'children': {'uncloud': {
            'vars': {'ansible_user': 'ucdeploy'}, 'hosts': {
                'example-b': {'ansible_host': '192.0.2.20'},
                'example-a': {'ansible_host': '192.0.2.10'}}}}}}))
        self.document = {'files': {'install.json': '{"company":"example"}\n'}, 'status': 'installed_and_verified'}
        self.master = b'x' * 32
        values = {trust_name('example', 'vault_certlocker_initial_admin_email'): 'admin@example.com',
                  trust_name('example', 'vault_certlocker_company_account_domain'): 'example.com',
                  trust_name('example', 'vault_certlocker_master_key'): base64.b64encode(self.master).decode()}
        self.operator = Mock()
        self.operator.get.side_effect = values.get
        self.owner = {'account_id': 'installed-account', 'user_id': 'installed-superuser'}
        self.stored = None
        for name, value in [('inventory_directory', self.root), ('runtime_ssh_key', Path('/dev/shm/identity'))]:
            p = patch.object(archive, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def encrypted(self, plain):
        nonce = b'n' * 12
        return 'OB:' + base64.b64encode(nonce).decode() + ':' + base64.b64encode(
            AESGCM(self.master).encrypt(nonce, plain.encode(), None)).decode()

    def query(self, key, primary, user, known_hosts, sql):
        self.assertEqual(primary, '192.0.2.20')
        self.assertEqual(key, Path('/dev/shm/identity'))
        self.assertEqual(known_hosts, self.root / 'known_hosts')
        self.assertNotIn(self.document['files']['install.json'], sql)
        if 'FROM jeremy.users' in sql:
            return [self.owner]
        self.assertIn('FROM jeremy.private_secrets WHERE id=', sql)
        return [self.stored] if self.stored else None

    def load(self, args, values):
        self.assertEqual(set(values['uncloud_certificate_seed']), {'private_secrets'})
        rows = values['uncloud_certificate_seed']['private_secrets']
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['secret']), {'value': self.document})
        self.assertNotIn(rows[0]['secret'], ' '.join(map(str, args)))
        self.assertIn('StrictHostKeyChecking=yes', ' '.join(map(str, args)))
        row = rows[0]
        self.stored = {key: row[key] for key in ('id', 'account_id', 'user_id', 'name', 'secret_type')}
        self.stored['secret'] = self.encrypted(row['secret'])

    def save(self):
        return archive.archive_customer_installation('example', self.config, self.cycle,
                                                      self.document, 'a' * 64, self.operator)

    def test_customer_copy_uses_installed_account_and_encrypted_exact_readback(self):
        with patch.object(archive, 'database_query', side_effect=self.query), \
                patch.object(archive, 'run_ansible', side_effect=self.load) as load:
            result = self.save()
            self.assertEqual(result['status'], 'saved')
            self.assertEqual(result['account_id'], 'installed-account')
            self.assertEqual(self.stored['user_id'], 'installed-superuser')
            self.assertEqual(self.save(), result)
            load.assert_called_once()

    def test_different_customer_content_is_never_overwritten_or_claimed_saved(self):
        with patch.object(archive, 'database_query', side_effect=self.query), \
                patch.object(archive, 'run_ansible', side_effect=self.load) as load:
            self.save()
            self.stored['secret'] = self.encrypted(json.dumps({'value': {'wrong': 'snapshot'}}))
            with self.assertRaisesRegex(RuntimeError, 'read-back did not match'):
                self.save()
            load.assert_called_once()

    def test_customer_identity_and_owner_must_match(self):
        with patch.object(archive, 'database_query', side_effect=self.query), \
                patch.object(archive, 'run_ansible', side_effect=self.load):
            self.save()
            self.stored['user_id'] = 'someone-else'
            with self.assertRaisesRegex(RuntimeError, 'identity differs'):
                self.save()

    def test_missing_or_ambiguous_superuser_stops_before_write(self):
        for owners in (None, [], [self.owner, self.owner]):
            with self.subTest(owners=owners), patch.object(archive, 'database_query', return_value=owners), \
                    patch.object(archive, 'run_ansible') as load:
                with self.assertRaisesRegex(ValueError, 'exactly one active'):
                    self.save()
                load.assert_not_called()

    def test_loader_failure_is_reported_without_command_or_payload(self):
        with patch.object(archive, 'database_query', side_effect=self.query), \
                patch.object(archive, 'run_ansible', side_effect=subprocess.CalledProcessError(1, ['private-argv'])):
            with self.assertRaisesRegex(RuntimeError, 'archive loader did not complete') as caught:
                self.save()
        self.assertNotIn('private-argv', str(caught.exception))

    def test_inventory_mismatch_prevents_customer_access(self):
        self.cycle['nodes']['example-a']['public_ip'] = '192.0.2.99'
        with patch.object(archive, 'database_query') as query, patch.object(archive, 'run_ansible') as load:
            with self.assertRaisesRegex(ValueError, 'target differs'):
                self.save()
        query.assert_not_called()
        load.assert_not_called()

    def test_ciphertext_or_key_corruption_fails_readback(self):
        row = {'id': 'record', 'secret': self.encrypted(json.dumps({'value': self.document}))}
        expected = {'id': 'record'}
        for value in ('plaintext', 'OB:invalid:invalid'):
            with self.subTest(value=value):
                row['secret'] = value
                with self.assertRaisesRegex(RuntimeError, 'read-back did not match'):
                    archive.verify_customer_copy(row, expected, self.document, self.master)
        row['secret'] = self.encrypted(json.dumps({'value': self.document}))
        with self.assertRaisesRegex(RuntimeError, 'read-back did not match'):
            archive.verify_customer_copy(row, expected, self.document, b'z' * 32)


if __name__ == '__main__':
    unittest.main()
