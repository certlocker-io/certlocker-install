import contextlib
import importlib.machinery
import importlib.util
import json
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import uncloud_config as wizard
import uncloud_install_preflight as dependencies
from uncloud_access import CERTLOCKER_UPDATER_CIDRS, monitoring_access, with_updater
import uncloud_smtp as smtp
from uncloud_support import bundled_release_manifest
from controller_runtime import container_arguments


def workflow_module():
    loader = importlib.machinery.SourceFileLoader('customer_workflow', str(ROOT / 'scripts/uncloud'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def company_config():
    return {
        'company': 'example', 'trust_group': 'Example', 'deployment': 'prod',
        'google_project': 'example-project', 'ssh_user': 'ucdeploy',
        'ssh_private_key': '~/.ssh/certlocker-example',
        'nodes': {'example-a': {'zone': 'europe-west1-b', 'machine_type': 'e2-standard-2'},
                  'example-b': {'zone': 'europe-west4-a', 'machine_type': 'e2-standard-2'}},
        'boot_disk_size_gb': 100, 'vpn_cidrs': [], 'certificate_mode': 'customer',
        'dns_zone': 'example.com', 'acme_email': 'admin@example.com',
        'front_url': 'https://certlocker.example.com',
        'backoffice_url': 'https://backoffice.example.com',
        'grafana_url': 'https://grafana.example.com', 'initial_admin_email': 'admin@example.com',
        'account_domain': 'example.com', 'smtp_mode': 'managed',
        'registry_mode': 'ghcr', 'runtime_backend': 'host',
    }


class StopBeforeCloudChanges(Exception):
    pass


class GuidedInstallTests(unittest.TestCase):
    def test_required_selection_reprompts_on_blank_and_disabled(self):
        with patch('builtins.input', side_effect=['', 'disabled', '2']) as prompt, \
                contextlib.redirect_stdout(io.StringIO()):
            selected = wizard.choose('Application mail', [('customer', 'Customer SMTP'),
                                                          ('managed', 'Managed mail')])
        self.assertEqual(selected, 'managed')
        self.assertEqual(prompt.call_count, 3)
        self.assertEqual(prompt.call_args.args, ('Application mail: ',))

    def test_mail_setup_and_refresh_reject_disabled_or_missing_selection(self):
        for operation in (smtp.enroll_smtp, smtp.refresh_smtp):
            for mode in ('disabled', None):
                with self.subTest(operation=operation.__name__, mode=mode):
                    trust = Mock()
                    trust.get.return_value = {'smtp_enabled': False}
                    with patch.object(smtp, 'verify_smtp') as verify, \
                            patch.object(smtp, 'replace_configuration') as save, \
                            contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(ValueError, 'Application mail is required'):
                            operation('example', trust, {'smtp_mode': mode}, non_interactive=True)
                    verify.assert_not_called()
                    save.assert_not_called()

    def test_managed_mail_requires_provisioned_credentials(self):
        trust = Mock()
        trust.get.side_effect = lambda name: {'smtp_enabled': False} if name.endswith(smtp.SETTINGS) else smtp.MISSING
        with self.assertRaisesRegex(ValueError, 'Managed application mail is not provisioned'):
            smtp.enroll_smtp('example', trust, {'smtp_mode': 'managed'}, non_interactive=True)
        trust.populate_empty.assert_not_called()

    def test_customer_mail_authenticates_before_saving(self):
        trust = Mock()
        trust.get.side_effect = [{'smtp_enabled': False}, smtp.MISSING]
        trust.populate_empty.side_effect = lambda company, key, value: value
        config = {'smtp_mode': 'customer', 'smtp_host': 'smtp.example.com',
                  'smtp_user': 'mail@example.com', 'smtp_tls': 'starttls', 'smtp_port': 587}
        with patch.dict(os.environ, {'CERTLOCKER_SMTP_PASSWORD': 'test-password'}), \
                patch.object(smtp, 'verify_smtp', side_effect=ValueError('Authentication failed')), \
                patch.object(smtp, 'replace_configuration') as save:
            with self.assertRaisesRegex(ValueError, 'Authentication failed'):
                smtp.enroll_smtp('example', trust, config, non_interactive=True)
        trust.populate_empty.assert_not_called()
        save.assert_not_called()

    def test_both_updater_addresses_are_automatic_and_hidden_from_customer_prompt(self):
        expected = ['185.88.0.182/32', '198.51.100.21/32', '88.81.117.228/32']
        self.assertEqual(with_updater(['198.51.100.21/32']), expected)
        self.assertEqual(with_updater(expected), expected)
        self.assertEqual(monitoring_access([], supplied='198.51.100.21'), expected)
        with patch('builtins.input', return_value='') as prompt:
            self.assertEqual(monitoring_access(expected, interactive=True), expected)
        self.assertNotIn('88.81.117.228', prompt.call_args.args[0])
        self.assertNotIn('185.88.0.182', prompt.call_args.args[0])

    def test_controller_forwards_trust_token_by_environment_name_only(self):
        with tempfile.TemporaryDirectory() as temp, patch('controller_runtime.Path.home', return_value=Path(temp)), \
                patch.dict(os.environ, {'TRUST_TOKEN': 'test-deployment-token', 'CERTLOCKER_ACCOUNT_ID': 'customer-account'}, clear=True):
            command = container_arguments('uncloud', ['up'], 'example-controller')
        self.assertIn('TRUST_TOKEN', command)
        self.assertIn('CERTLOCKER_ACCOUNT_ID', command)
        self.assertNotIn('customer-account', command)
        self.assertNotIn('test-deployment-token', ' '.join(command))
        self.assertEqual(command[-2:], ['scripts/uncloud', 'up'])

    def test_check_reuses_generated_profile_without_setup_questions(self):
        module = workflow_module()
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            profile = Path(temp) / 'example.json'
            profile.write_text(json.dumps(company_config()))
            stack.enter_context(patch.object(module, 'resolve_company_config', return_value=profile))
            stack.enter_context(patch.object(module, 'configure'))
            stack.enter_context(patch.object(module, 'can_prompt', return_value=False))
            report = stack.enter_context(patch.object(module, 'check_company_status', return_value={'phase': 'paused'}))
            questions = stack.enter_context(patch.object(wizard, 'collect'))
            module.main(['check'])
            report.assert_called_once_with(profile)
            questions.assert_not_called()

    def test_up_without_config_runs_wizard_and_saves_private_profile(self):
        module = workflow_module()
        config = company_config()
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(module, 'ROOT', Path(temp)))
            stack.enter_context(patch.object(module, 'can_prompt', return_value=True))
            stack.enter_context(patch.object(module, 'require_new_company'))
            stack.enter_context(patch.object(module, 'operator_cidr', return_value='198.51.100.10/32'))
            stack.enter_context(patch('uncloud_preflight.check_controller'))
            stack.enter_context(patch.object(wizard, 'ask', return_value='example'))
            collect = stack.enter_context(patch.object(wizard, 'collect', return_value=config))
            stack.enter_context(patch.object(module, 'configure', side_effect=StopBeforeCloudChanges))
            with self.assertRaises(StopBeforeCloudChanges):
                module.main(['up'])
            collect.assert_called_once_with('example', None, None)
            profile = Path(temp) / 'uncloud/environments/example.json'
            saved = json.loads(profile.read_text())
            self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
            self.assertEqual(saved['nodes'], config['nodes'])
            self.assertTrue(set(CERTLOCKER_UPDATER_CIDRS).issubset(saved['operator_cidrs']))
            self.assertNotIn('TRUST_TOKEN', saved)
            self.assertNotIn('CERTLOCKER_TOKEN', saved)
            self.assertFalse(any('address' in node for node in saved['nodes'].values()))

    def test_wizard_collects_google_settings_without_existing_vms_or_key(self):
        def google(*args):
            if args[:2] == ('compute', 'zones'):
                return [{'name': 'europe-west1-b', 'status': 'UP'},
                        {'name': 'europe-west4-a', 'status': 'UP'}]
            return {'guestCpus': 2, 'memoryMb': 8192}

        def ask(prompt, default=None, validate=None):
            self.assertNotIn('Grafana', prompt)
            overrides = {'Cloudflare DNS zone': 'example.com',
                         'Company superuser email': 'admin@example.com',
                         'Additional customer VPN / whitelist IPv4 addresses, comma-separated':
                             '198.51.100.21,198.51.100.22/32'}
            value = overrides.get(prompt, default)
            return validate(value) if validate else value

        def choose(prompt, options, default=None, **kwargs):
            if prompt == 'Application mail':
                self.assertIsNone(default)
                self.assertEqual([value for value, _ in options], ['customer', 'managed'])
                return 'managed'
            return {'Deployment type': 'prod'}.get(prompt, default)

        with patch.object(wizard, 'choose_google_project', return_value='example-project'), \
                patch.object(wizard, 'google', side_effect=google), \
                patch.object(wizard, 'ask', side_effect=ask), \
                patch.object(wizard, 'choose', side_effect=choose), \
                patch('uncloud_support.ensure_certlocker_token') as token:
            config = wizard.collect('example')
        self.assertEqual(config['google_project'], 'example-project')
        self.assertEqual(set(config['nodes']), {'example-a', 'example-b'})
        self.assertEqual(config['ssh_private_key'], '~/.ssh/certlocker-example')
        self.assertEqual(config['ssh_user'], 'ucdeploy')
        self.assertEqual(config['vpn_cidrs'], ['198.51.100.21/32', '198.51.100.22/32'])
        self.assertEqual(config['grafana_url'], 'https://grafana-cl-example.example.com')
        self.assertEqual(config['registry_mode'], 'ghcr')
        token.assert_called_once_with(interactive=True)

    def test_terraform_outputs_feed_setup_and_pinned_manifest(self):
        module = workflow_module()
        config = company_config()
        nodes = {name: {'public_ip': address, 'private_ip': private,
                        'zone': config['nodes'][name]['zone'], 'status': 'RUNNING',
                        'instance_id': str(index)}
                 for index, (name, address, private) in enumerate([
                     ('example-a', '192.0.2.10', '10.44.10.10'),
                     ('example-b', '192.0.2.20', '10.44.20.10')], 1)}
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            state = Path(temp)
            for name, value in [('STATE', state), ('NAMES', tuple(config['nodes'])),
                                ('ZONES', {name: node['zone'] for name, node in config['nodes'].items()}),
                                ('MACHINE_NAMES', {name: name for name in config['nodes']}),
                                ('COMPANY', 'example'), ('TRUST_GROUP', 'Example'), ('DNS_ZONE', 'example.com'),
                                ('LAB_NAMES', ('certlocker.example.com', 'backoffice.example.com'))]:
                stack.enter_context(patch.object(module, name, value))
            trust = Mock()
            trust.get.return_value = {'hostname': 'certlocker.example.com',
                                     'backoffice_hostname': 'backoffice.example.com',
                                     'grafana_hostname': 'grafana.example.com'}
            stack.enter_context(patch('uncloud_support.Trust', return_value=trust))
            stack.enter_context(patch('uncloud_support.inventory_directory', return_value=state / 'inventory'))
            workflow = module.Workflow.__new__(module.Workflow)
            workflow.action = 'up'
            workflow.config = config
            workflow.until = 'apps'
            workflow.interactive_setup = True
            workflow.bootstrap_manifest = str(ROOT / 'releases/current.json')
            workflow.apply = Mock(return_value={'create': 2})
            workflow.tf = Mock(return_value=json.dumps(nodes))
            workflow.save = Mock()
            workflow.command = Mock(side_effect=StopBeforeCloudChanges)
            with self.assertRaises(StopBeforeCloudChanges):
                workflow.up({})
            workflow.apply.assert_called_once_with()
            command = workflow.command.call_args.args[0]
            self.assertEqual(command[0], ROOT / 'scripts/setup-ha')
            self.assertEqual(command[1:4], ['example', '192.0.2.10', '192.0.2.20'])
            self.assertIn('provider_1=supplied', command)
            self.assertEqual(command[command.index('--manifest-file') + 1], workflow.bootstrap_manifest)
            generated = json.loads(Path(command[command.index('--config') + 1]).read_text())
            self.assertEqual(generated['nodes']['example-a']['wireguard_endpoint'], '10.44.10.10')
            self.assertEqual(generated['hosting']['provider'], 'google')

    def test_terraform_identity_and_plan_guards_are_present(self):
        module = workflow_module()
        with self.assertRaises(ValueError):
            module.validate_plan({'resource_changes': [{'address': 'foreign.resource',
                'change': {'actions': ['delete']}}]}, 'example-project', False)
        manifest, _ = bundled_release_manifest(ROOT / 'releases/current.json')
        self.assertEqual(manifest['release'], 'prod_1.1.28')

    def test_preflight_pins_bundled_release_and_resume_preserves_it(self):
        config = company_config()
        trust = Mock()
        trust.ensure.side_effect = lambda company, name, factory: factory()
        settings = {'certificate_mode': 'customer',
                    'acme_directory': 'https://acme-v02.api.letsencrypt.org/directory',
                    'profile': 'shortlived'}
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            state = Path(temp)
            for name, value in [('enroll', settings), ('cloudflare_preflight', ('example-credential', 'example-zone')),
                                ('check_access', None), ('check_dns_ownership', None),
                                ('acme_profile_preflight', None), ('enroll_smtp', {'smtp_enabled': True})]:
                stack.enter_context(patch.object(dependencies, name, return_value=value))
            stack.enter_context(patch.object(dependencies, 'Cloudflare'))
            stack.enter_context(patch('uncloud_install_notification.preflight', return_value='configured'))
            stack.enter_context(patch.object(dependencies, 'inventory_directory', return_value=state / 'inventory'))
            first = dependencies.check_dependencies('example', trust, config, state)
            with patch.object(dependencies, 'bundled_release_manifest', side_effect=AssertionError('Resume must use saved pin')):
                second = dependencies.check_dependencies('example', trust, config, state)
            self.assertEqual(first['release'], 'prod_1.1.28')
            self.assertEqual(second['release'], first['release'])
            manifest = Path(first['manifest_file'])
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('example-credential', manifest.read_text())


if __name__ == '__main__':
    unittest.main()
