"""Exercise InstallConfigDTO and its referenced secret payloads through the Gateway client."""
import base64
from contextlib import ExitStack
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_install_token_group import Gateway
from uncloud_host_access import generate_key, google_setup_key, public_key, runtime_ssh_key
from uncloud_install_setup import connect, read_credentials


def setup_entrypoint():
    script = Path(__file__).resolve().parents[1] / 'scripts/setup-ha'
    loader = importlib.machinery.SourceFileLoader('supplied_install_setup', str(script))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


class InstallSetupTests(unittest.TestCase):
    def setUp(self):
        self.group = 'site-a'
        self.gateway = Gateway(groupAccess=[self.group])
        self.enterContext(self.gateway.connect())
        self.enterContext(patch.dict(os.environ, {'TRUST_TOKEN': 'install-token'}, clear=True))
        self.config = {}
        self.trust = connect(self.config, 'acct', False)
        self.master = base64.b64encode(bytes(range(32))).decode()
        self.setup = dict(account_id='acct', install_type='GCP', user_email='Admin@example.com',
                          access_token='install-token', gateway_url='https://unused.invalid',
                          master_key_secret_id='master-id', email_secret_id='mail-id')
        self.record('-master-key', 'master-id', dict(value=self.master))
        self.record('-email', 'mail-id', dict(smtp_host='smtp.example.com', smtp_port='587',
                    smtp_username='mail@example.com', smtp_password='password-fixture', auth='true',
                    smtp_ssl=False, start_tls=True, ssl_trust='*'))

    def record(self, suffix, identifier, body):
        name = self.group + suffix
        self.gateway.records[name] = dict(name=name, id=identifier, groups=[self.group], secret=json.dumps(body))

    def load(self, provider='GCP'):
        self.record('_install_config', 'config-id', self.setup)
        credentials = read_credentials(self.trust, self.config, provider)
        credentials.enroll('test', self.trust)
        return credentials.pem

    def test_gcp_without_pem_imports_credentials_and_supports_retry(self):
        self.assertIsNone(self.load())
        self.assertIsNone(self.load())
        self.assertEqual(self.config['smtp_tls'], 'starttls')
        self.assertEqual(self.config['initial_admin_email'], 'admin@example.com')
        self.assertEqual(self.config['trust_account_id'], 'acct')
        self.assertNotIn('additional_ssh_key', self.config)
        for secret in ('password-fixture', self.master, 'install-token'):
            self.assertNotIn(secret, json.dumps(self.config))
        self.assertTrue(all(request.full_url.startswith('https://trust.certlocker.io/rest/')
                            for request in self.gateway.requests))

    def test_service_urls_must_belong_to_the_zone_for_both_providers(self):
        for kind, provider in [('GENERIC', 'supplied'), ('GCP', 'GCP')]:
            with self.subTest(kind=kind):
                self.setup.update(install_type=kind, dns_zone='example.org', front_url='https://app.other.org')
                self.record('_install_config', 'config-id', self.setup)
                with self.assertRaisesRegex(ValueError, 'inside the DNS zone'):
                    read_credentials(self.trust, {}, provider)

    def test_config_delivers_image_access_only_in_memory(self):
        self.record('-cloudflare', 'dns-id', {'value': 'dns-fixture'})
        self.setup.update(cloudflare_secret_id='dns-id', dns_zone='example.org')
        for provider in ('GCP', 'supplied'):
            self.setup['install_type'] = 'GCP' if provider == 'GCP' else 'GENERIC'
            if provider == 'supplied':
                self.setup['pem_secret_id'] = 'ssh-id'
                self.record('-ssh', 'ssh-id', dict(username='deploy', key=generate_key()))
            encoded = base64.b64encode(b'release-reader:ghp_fixture').decode()
            self.setup['image_pull_access'] = encoded
            self.record('_install_config', 'config-id', self.setup)
            config = {}
            credentials = read_credentials(self.trust, config, provider)
            self.assertEqual(credentials.cloudflare_api_token, 'dns-fixture')
            self.assertNotIn('dns-fixture', json.dumps(config))
            self.assertEqual(config['dns_zone'], 'example.org')
            self.assertEqual(credentials.image_pull_token, 'ghp_fixture')
            self.assertEqual(config['ghcr_username'], 'release-reader')
            self.assertNotIn('ghp_fixture', json.dumps(config))
            self.assertNotIn(encoded, json.dumps(config))
            self.setup['image_pull_access'] = 'malformed!'
            self.record('_install_config', 'config-id', self.setup)
            with self.assertRaisesRegex(ValueError, 'Invalid release image access'):
                read_credentials(self.trust, {}, provider)

    def test_generic_network_and_scoped_cloudflare_reference(self):
        self.setup.update(install_type='GENERIC', pem_secret_id='ssh-id', cloudflare_secret_id='dns-id',
                          server_hostnames=['node-a', 'node-b'], dns_zone='example.org',
                          front_url='https://ui.example.org', backoffice_url='https://admin.example.org',
                          grafana_url='https://grafana.example.org')
        self.record('-ssh', 'ssh-id', dict(username='ubuntu', key=generate_key()))
        self.setup.update(admin_password_secret_id='admin-id', deployment_options={
            'deployment':'prod', 'peer_ips':['10.1.0.2','10.1.0.3'], 'vpn_ips':['192.0.2.30'],
            'ingress_cidrs':['10.2.0.0/24'], 'admin_email':'operator@example.org',
            'acme_email':'certs@example.org', 'account_domain':'example.org', 'admin_display_name':'Lab Admin'})
        self.record('-admin-password', 'admin-id', dict(value='first-login-fixture'))
        self.record('-cloudflare', 'dns-id', dict(value='dns-fixture'))
        self.record('_install_config', 'config-id', self.setup)
        credentials = read_credentials(self.trust, self.config, 'supplied')
        self.assertEqual(credentials.cloudflare_api_token, 'dns-fixture')
        self.assertNotIn('dns-fixture', json.dumps(self.config))
        self.assertNotIn('first-login-fixture', json.dumps(self.config))
        self.assertEqual(credentials.admin_password, 'first-login-fixture')
        self.assertEqual(self.config['peer_ips'], ['10.1.0.2','10.1.0.3'])
        self.assertEqual(self.config['initial_admin_email'], 'operator@example.org')
        self.assertEqual(self.config['vpn_cidrs'], ['192.0.2.30/32'])
        self.assertEqual(self.config['deployment'], 'prod')
        for field in ('dns_zone', 'front_url', 'grafana_url', 'backoffice_url', 'server_hostnames'):
            self.assertEqual(self.config[field], self.setup[field])

    def test_smtp_settings_follow_the_ui_and_plaintext_password_auth_is_rejected(self):
        record = self.gateway.records[self.group + '-email']
        mail = json.loads(record['secret'])
        mail.update(auth='false', start_tls=False, smtp_ssl=False, ssl_trust='mail.example.com')
        record['secret'] = json.dumps(mail)
        self.load()
        self.assertFalse(self.config['smtp_auth'])
        self.assertEqual(self.config['smtp_tls'], 'none')
        self.assertEqual(self.config['smtp_ssl_trust'], 'mail.example.com')
        mail['auth'] = 'true'
        record['secret'] = json.dumps(mail)
        with self.assertRaisesRegex(ValueError, 'requires STARTTLS'):
            self.load()

    def test_pem_is_additional_public_access_for_google_and_existing_identity_for_supplied(self):
        private = generate_key().strip()
        self.record('-ssh', 'ssh-id', dict(username='ubuntu', key=private))
        self.setup['pem_secret_id'] = 'ssh-id'
        self.load()
        self.assertEqual(self.config['additional_ssh_key'], 'ubuntu:' + public_key(private))
        self.config = {}
        self.setup['install_type'] = 'GENERIC'
        self.assertEqual(self.load('supplied'), dict(username='ubuntu', key=private))
        self.assertNotIn(private, json.dumps(self.config))

    def test_account_provider_or_reference_mismatch_fails_before_writes(self):
        for field, value in [('account_id', 'another'), ('install_type', 'GENERIC'),
                             ('master_key_secret_id', 'unrelated'), ('access_token', 'other-token')]:
            with self.subTest(field=field), patch.dict(self.setup, {field: value}):
                with self.assertRaises(ValueError):
                    self.load()
        self.assertFalse(any(req.get_method() == 'POST' for req in self.gateway.requests))

    def test_replacement_token_for_same_account_and_config_can_resume(self):
        self.load()
        self.gateway.metadata['id'] = 'replacement-token'
        with patch.dict(os.environ, {'CERTLOCKER_TOKEN': 'replacement-token'}):
            self.trust = connect(self.config, None, False)
            self.load()
        with patch.dict(self.config, {'install_config_id': 'different-config'}):
            with self.assertRaisesRegex(ValueError, 'differs from the saved installation'):
                self.load()

    def test_google_keys_are_unique_per_install_and_stable_on_resume(self):
        config = dict(install_config_id='config-id', trust_account_id='acct', ssh_private_key='logical')
        keys = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as state:
                with google_setup_key(config, state, allow_create=True) as first:
                    self.assertEqual(runtime_ssh_key('logical').stat().st_mode & 0o777, 0o600)
                with google_setup_key(config, state, allow_create=False) as second:
                    self.assertEqual(first, second)
                keys.append(first)
                (Path(state) / 'google-provisioning-key').unlink()
                with self.assertRaisesRegex(ValueError, 'original Google provisioning key'):
                    with google_setup_key(config, state, allow_create=True):
                        pass
        self.assertNotEqual(*keys)

    def test_bare_metal_readiness_fetches_only_the_referenced_ssh_identity(self):
        module = setup_entrypoint()
        key = generate_key()
        self.setup.update(install_type='GENERIC', pem_secret_id='ssh-id')
        self.record('-ssh', 'ssh-id', dict(username='deploy', key=key.strip()))
        self.record('_install_config', 'config-id', self.setup)
        addresses = ('192.0.2.11', '192.0.2.12')
        used = []

        def inspect(names, targets, nodes, path, user, **kwargs):
            self.assertEqual(targets, addresses)
            self.assertEqual(user, 'deploy')
            if 'server_hostnames' in self.setup:
                self.assertEqual([nodes[n]['expected_hostname'] for n in names], self.setup['server_hostnames'])
            self.assertTrue(Path(path).read_text() == key)
            used.append(Path(path))
            return {}, []

        with tempfile.TemporaryDirectory() as temporary, patch('uncloud_bare_metal.inspect_pair', side_effect=inspect):
            state = Path(temporary) / 'state'
            args = ['--bare-metal', 'test', '--account-id', 'acct', '--state-dir', str(state),
                    '--preflight-only', '--non-interactive']
            module.main([*args[:2], *addresses, *args[2:]])
            self.setup['server_ips'] = list(addresses)
            self.setup['server_hostnames'] = ['node-a', 'node-b']
            self.record('_install_config', 'config-id', self.setup)
            module.main(args)
            self.assertEqual(len(used), 2)
            self.assertFalse(used[0].exists())
            self.assertFalse(state.exists())
            self.assertEqual([r.full_url.rsplit('/', 1)[1] for r in self.gateway.requests if '/fetch/' in r.full_url],
                             ['config-id', 'ssh-id'] * 2)
            self.assertTrue(all(r.get_method() == 'GET' for r in self.gateway.requests))
            with self.assertRaisesRegex(ValueError, 'addresses differ from Trust'):
                module.main([*args[:2], *reversed(addresses), *args[2:]])
            self.setup['pem_secret_id'] = 'unrelated'
            self.record('_install_config', 'config-id', self.setup)
            with self.assertRaisesRegex(ValueError, 'differs from its group record'):
                module.main(args)
            self.assertEqual(len(used), 2)

    def test_supplied_server_entrypoint_uses_trust_pem_for_both_hosts_on_setup_and_resume(self):
        module = setup_entrypoint()
        key = generate_key()
        self.setup.update(install_type='GENERIC', pem_secret_id='ssh-id')
        self.record('-ssh', 'ssh-id', dict(username='ubuntu', key=key.strip()))
        self.record('_install_config', 'config-id', self.setup)
        addresses = ['192.0.2.11', '192.0.2.12']
        used = []

        def wait_for_ssh(path, address, *, user):
            self.assertEqual(Path(path).read_text(), key)
            self.assertEqual(user, 'ubuntu')
            used.append((Path(path), address))

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            profile = root / 'profile.json'
            profile.write_text(json.dumps(dict(deployment='dev', nodes={'test-a': {}, 'test-b': {}},
                operator_cidrs=['192.0.2.1/32'], vpn_cidrs=['192.0.2.1/32'], certificate_mode='customer',
                dns_zone='example.com', acme_email='acme@example.com')))
            stack.enter_context(patch('uncloud_preflight.check_controller'))
            stack.enter_context(patch.object(module, 'inventory_directory', return_value=root / 'inventory'))
            stack.enter_context(patch.object(module, 'prepare_ssh'))
            stack.enter_context(patch.object(module, 'wait_for_ssh', side_effect=wait_for_ssh))
            stack.enter_context(patch.object(module, 'resolve_node', side_effect=lambda provider, address, name, cfg:
                                     dict(ansible_host=address, uncloud_expected_hostname=name, uncloud_provider=provider)))
            stack.enter_context(patch.object(module, 'run'))
            args = ['test', *addresses, '--provider-1', 'supplied', '--provider-2', 'supplied',
                    '--account-id', 'acct', '--config', str(profile), '--state-dir', str(root / 'state'),
                    '--manifest-file', str(profile), '--non-interactive', '--until', 'harden']
            module.main(args)
            self.gateway.metadata['id'] = 'replacement-token'
            with patch.dict(os.environ, {'CERTLOCKER_TOKEN': 'replacement-token'}):
                module.main(args)
            saved = (root / 'state/installation.json').read_text()
            for secret in ('password-fixture', 'install-token', self.master, 'PRIVATE KEY'):
                self.assertNotIn(secret, saved)
        self.assertEqual([address for _, address in used], addresses * 2)
        self.assertTrue(all(not path.exists() for path, _ in used))

    def test_local_operator_gateway(self):
        with patch.dict(os.environ, {'CERTLOCKER_INSTALL_TRUST_URL': 'http://localhost:8080/gateway/rest/api'}):
            self.assertEqual(connect({}, 'acct', False).api_url, 'http://localhost:8080/gateway/rest')
            self.assertEqual(self.gateway.requests[-1].full_url,
                             'http://localhost:8080/gateway/rest/api/v1/token/acct/get/install-token')

    def test_reject_remote_plain_http(self):
        with patch.dict(os.environ, {'CERTLOCKER_INSTALL_TRUST_URL': 'http://example.com/rest'}):
            with self.assertRaisesRegex(ValueError, 'HTTP requires localhost'):
                connect({}, 'acct', False)

    def test_new_setup_requires_customer_account(self):
        with self.assertRaisesRegex(ValueError, 'ACCOUNT_ID'):
            connect({}, None, False)
