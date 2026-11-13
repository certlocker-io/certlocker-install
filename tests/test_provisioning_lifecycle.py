"""Exercise provisioning, recovery and cleanup with real throwaway SSH identities."""
from contextlib import ExitStack
import importlib.machinery
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import uncloud_host_access as access
from uncloud_support import MISSING, company_trust_record_names


class OperatorTrust:
    def __init__(self):
        self.records = {}
        self.fail_write = False
        self.fail_readback = False

    def get(self, name):
        if self.fail_readback and name in self.records:
            return MISSING
        return self.records.get(name, MISSING)

    def ensure_named(self, name, company, factory, **kwargs):
        if self.fail_write:
            raise RuntimeError('Trust write unavailable')
        if name not in self.records:
            self.records[name] = factory()
        return self.records[name]


def workflow_module():
    loader = importlib.machinery.SourceFileLoader('key_lifecycle_workflow', str(ROOT / 'scripts/uncloud'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class ProvisioningLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.source = self.root / '.ssh/certlocker-example'
        self.state = self.root / 'state'
        self.config = {
            'company': 'example', 'trust_group': 'Example', 'deployment': 'prod',
            'trust_account_id': 'customer-account',
            'ssh_private_key': str(self.source), 'ssh_user': 'ucdeploy',
            'google_project': 'example-project', 'registry_mode': 'ghcr',
            'nodes': {'example-a': {'zone': 'europe-west1-b'},
                      'example-b': {'zone': 'europe-west4-a'}},
        }
        self.trust = OperatorTrust()
        self.factory = self.stack.enter_context(patch.object(access, 'Trust', return_value=self.trust))
        self.stack.enter_context(patch.object(access, 'inventory_directory', return_value=self.root / 'inventory'))
        self.stack.enter_context(patch.dict(os.environ))
        for name in ('CERTLOCKER_SSH_KEY_SOURCE', 'CERTLOCKER_SSH_KEY_PATH'):
            os.environ.pop(name, None)

    def start(self, **kwargs):
        return access.setup_key('example', self.config, self.state, **kwargs)

    def original(self):
        return self.trust.records[access.provisioning_record('example')]

    def test_fresh_key_is_in_operator_trust_before_it_can_be_used(self):
        with self.start(allow_create=True) as public:
            path = access.runtime_ssh_key(self.source)
            self.assertTrue(path.is_relative_to('/dev/shm'))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(), self.original())
            self.assertFalse(self.source.exists())
            derived = subprocess.run(['ssh-keygen', '-y', '-f', str(path)],
                                     check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(derived, public)
            snapshot = (self.state / 'provisioning-key.json').read_text()
            self.assertNotIn(self.original(), snapshot)
            self.assertIn(public, snapshot)
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())
        self.assertFalse(self.source.parent.exists())
        self.assertNotIn('CERTLOCKER_SSH_KEY_PATH', os.environ)
        self.factory.assert_called_once_with(api_url='https://trust.certlocker.io/rest', group='Example', account_id='customer-account')

    def test_resume_uses_the_identical_remote_key_without_a_local_copy(self):
        with self.start(allow_create=True):
            original = self.original()
        with patch.object(access, 'generate_key', side_effect=AssertionError('Rotated on resume')):
            with self.start() as public:
                path = access.runtime_ssh_key(self.source)
                self.assertEqual(path.read_text(), original)
                self.assertEqual(public, access.public_key(original))
        self.assertFalse(path.exists())
        self.assertFalse(self.source.exists())

    def test_missing_original_in_trust_stops_resume_without_regeneration(self):
        with self.start(allow_create=True):
            pass
        self.trust.records.clear()
        with patch.object(access, 'generate_key', side_effect=AssertionError('Replaced missing identity')):
            with self.assertRaisesRegex(ValueError, 'will not generate a replacement'):
                with self.start():
                    self.fail('Resume used a replacement identity')
        self.assertFalse(self.source.exists())

    def workflow(self, action='up'):
        module = workflow_module()
        self.stack.enter_context(patch.object(module, 'STATE', self.state))
        self.stack.enter_context(patch.object(module, 'TERRAFORM', self.state / 'terraform'))
        self.stack.enter_context(patch.object(module, 'COMPANY', 'example'))
        workflow = module.Workflow.__new__(module.Workflow)
        workflow.config = self.config
        workflow.action = action
        workflow.run_dir = self.root / 'run'
        workflow.run_dir.mkdir(exist_ok=True)
        workflow.ssh_keys = self.stack.enter_context(ExitStack())
        workflow.progress = Mock()
        workflow.progress.stage.return_value = ExitStack()
        workflow.gcloud_rows = Mock(return_value=[])
        return workflow

    def test_fresh_up_recovers_checkpoint_left_by_older_teardown(self):
        with self.start(allow_create=True):
            original = self.original()
        snapshot = self.state / 'provisioning-key.json'
        previous = snapshot.read_text()
        self.trust.records.clear()
        workflow = self.workflow()
        public = workflow.prepare_ssh_identity()
        self.assertNotEqual(self.original(), original)
        self.assertEqual(public, access.public_key(self.original()))
        self.assertEqual((workflow.run_dir / 'retired-provisioning-key.json').read_text(), previous)
        self.assertEqual(json.loads(snapshot.read_text())['ssh_public_key'], public)
        self.assertEqual(workflow.gcloud_rows.call_count, 6)
        self.assertFalse(self.source.exists())

    def test_fresh_up_preserves_identity_when_google_has_leftovers_or_is_unavailable(self):
        with self.start(allow_create=True):
            pass
        self.trust.records.clear()
        snapshot = self.state / 'provisioning-key.json'
        original = snapshot.read_text()
        workflow = self.workflow()
        for rows in ([{'name': 'example-a'}], RuntimeError('Google unavailable')):
            with self.subTest(rows=rows), patch.object(access, 'generate_key') as generate:
                workflow.gcloud_rows.side_effect = rows if isinstance(rows, Exception) else None
                workflow.gcloud_rows.return_value = rows
                with self.assertRaises((ValueError, RuntimeError)):
                    workflow.prepare_ssh_identity()
                generate.assert_not_called()
                self.assertEqual(snapshot.read_text(), original)
                self.assertFalse((workflow.run_dir / 'retired-provisioning-key.json').exists())

    def test_workflow_does_not_retire_identity_for_resume_or_tracked_resources(self):
        with self.start(allow_create=True):
            pass
        self.trust.records.clear()
        snapshot = self.state / 'provisioning-key.json'
        original = snapshot.read_text()
        workflow = self.workflow('resume')
        for action in ('resume', 'up'):
            workflow.action = action
            if action == 'up':
                terraform = self.state / 'terraform'
                terraform.mkdir()
                (terraform / 'terraform.tfstate').write_text(json.dumps({
                    'resources': [{'mode': 'managed', 'type': 'google_compute_instance'}]}))
            with self.subTest(action=action), patch.object(access, 'generate_key') as generate:
                with self.assertRaisesRegex(ValueError, 'will not generate a replacement'):
                    workflow.prepare_ssh_identity()
                generate.assert_not_called()
                self.assertEqual(snapshot.read_text(), original)
        workflow.gcloud_rows.assert_not_called()

    def test_unreadable_terraform_state_cannot_authorize_a_new_identity(self):
        workflow = self.workflow()
        terraform = self.state / 'terraform'
        terraform.mkdir(parents=True)
        for contents in ('{', '[]', '{"resources": {}}', '{"resources": [null]}'):
            (terraform / 'terraform.tfstate').write_text(contents)
            with self.subTest(contents=contents), patch.object(access, 'generate_key') as generate:
                with self.assertRaisesRegex(ValueError, 'Cannot verify Terraform state'):
                    workflow.prepare_ssh_identity()
                generate.assert_not_called()
        workflow.gcloud_rows.assert_not_called()

    def test_destroy_retires_checkpoint_only_after_cloud_and_trust_cleanup(self):
        workflow = self.workflow('destroy')
        workflow.var_file = self.root / 'vars.json'
        workflow.evidence = {}
        workflow.remove_trust = True
        workflow.import_untracked_resources = Mock()
        workflow.tf = Mock(return_value='{}')
        workflow.state_resources = Mock(return_value=set())
        workflow.delete_orphaned_boot_disks = Mock()
        workflow.save = Mock()
        directory = self.root / 'inventory/uncloud/example'
        directory.mkdir(parents=True)
        marker = directory / '.setup.json'
        marker.write_text(json.dumps({'company': 'example', 'state_dir': str(self.state / 'installations/old')}))
        original_marker = marker.read_text()
        self.stack.enter_context(patch('uncloud_support.inventory_directory', return_value=directory))
        module = workflow_module()
        self.stack.enter_context(patch.object(module, 'ROOT', self.root))
        self.stack.enter_context(patch.object(module, 'LEGACY_STATE', self.root / 'legacy'))
        self.stack.enter_context(patch.object(Path, 'home', return_value=self.root / 'home'))
        with self.assertRaisesRegex(ValueError, 'already has installation records'):
            module.require_new_company('example')
        for failure in ('cloud', 'trust', None):
            with self.subTest(failure=failure):
                with self.start(allow_create=True):
                    pass
                snapshot = self.state / 'provisioning-key.json'
                previous = snapshot.read_text()
                workflow.gcloud_rows.return_value = [{'name': 'example-a'}] if failure == 'cloud' else []
                def revoke(*args, **kwargs):
                    self.assertTrue(snapshot.exists())
                    if failure == 'trust':
                        raise RuntimeError('Trust unavailable')
                    self.trust.records.clear()
                    return {'failed': []}
                with patch('uncloud_support.Trust', return_value=self.trust), \
                        patch('uncloud_support.discover_host_trust_names', return_value=[]), \
                        patch('uncloud_support.revoke_company_trust', side_effect=revoke):
                    if failure:
                        with self.assertRaises((ValueError, RuntimeError)):
                            workflow.apply(destroy=True)
                        self.assertEqual(snapshot.read_text(), previous)
                        self.assertEqual(marker.read_text(), original_marker)
                        self.assertFalse((workflow.run_dir / 'retired-inventory').exists())
                    else:
                        workflow.apply(destroy=True)
                        self.assertFalse(snapshot.exists())
                        self.assertEqual((workflow.run_dir / 'retired-provisioning-key.json').read_text(), previous)
                        self.assertFalse(directory.exists())
                        self.assertEqual((workflow.run_dir / 'retired-inventory/.setup.json').read_text(), original_marker)
                        module.require_new_company('example')
                        workflow.action = 'up'
                        workflow.prepare_ssh_identity()
                        self.assertTrue(snapshot.exists())

    def test_inventory_retirement_preserves_unowned_or_malformed_inventory(self):
        workflow = self.workflow('destroy')
        directory = self.root / 'inventory'
        directory.mkdir()
        with patch('uncloud_support.inventory_directory', return_value=directory):
            for identity in ([], {'company': 'other', 'state_dir': str(self.state)},
                             {'company': 'example', 'state_dir': str(self.root / 'foreign')}):
                with self.subTest(identity=identity):
                    marker = directory / '.setup.json'
                    marker.write_text(json.dumps(identity))
                    before = marker.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'not owned by this environment'):
                        workflow.retire_installation_inventory()
                    self.assertEqual(marker.read_bytes(), before)
                    self.assertFalse((workflow.run_dir / 'retired-inventory').exists())

    def test_write_failure_never_creates_a_persistent_key(self):
        self.trust.fail_write = True
        with self.assertRaisesRegex(RuntimeError, 'Trust write unavailable'):
            with self.start(allow_create=True):
                self.fail('Provisioning started without Trust storage')
        self.assertFalse(self.source.parent.exists())
        self.assertFalse((self.state / 'provisioning-key.json').exists())
        self.assertNotIn('CERTLOCKER_SSH_KEY_PATH', os.environ)

    def test_legacy_key_is_deleted_only_after_identical_trust_readback(self):
        original = access.generate_key()
        self.source.parent.mkdir()
        self.source.write_text(original)
        self.source.chmod(0o600)
        Path(str(self.source) + '.pub').write_text(access.public_key(original) + ' legacy-comment\n')
        with self.start():
            self.assertEqual(self.original(), original)
            self.assertFalse(self.source.exists())
            self.assertFalse(Path(str(self.source) + '.pub').exists())
            self.assertEqual(access.runtime_ssh_key(self.source).read_text(), original)
        with self.start():
            self.assertEqual(access.runtime_ssh_key(self.source).read_text(), original)

    def test_unverified_legacy_upload_preserves_the_only_original_copy(self):
        self.source.parent.mkdir()
        self.source.write_text(access.generate_key())
        self.source.chmod(0o600)
        self.trust.fail_readback = True
        with self.assertRaisesRegex(ValueError, 'read-back failed'):
            with self.start():
                self.fail('Provisioning used unverified storage')
        self.assertTrue(self.source.is_file())
        self.assertFalse((self.state / 'provisioning-key.json').exists())

    def test_replaced_remote_key_is_rejected_against_saved_fingerprint(self):
        with self.start(allow_create=True):
            pass
        self.trust.records[access.provisioning_record('example')] = access.generate_key()
        with self.assertRaisesRegex(ValueError, 'differs from the saved installation'):
            with self.start():
                self.fail('Provisioning used a rotated key')

    def test_interrupted_setup_removes_memory_copy_and_restores_environment(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.start(allow_create=True):
                path = access.runtime_ssh_key(self.source)
                raise KeyboardInterrupt()
        self.assertFalse(path.exists())
        self.assertFalse(self.source.exists())
        self.assertNotIn('CERTLOCKER_SSH_KEY_PATH', os.environ)
        self.assertTrue(self.original())

    def test_disk_backed_temporary_storage_is_rejected(self):
        with patch.object(access.subprocess, 'run', return_value=Mock(stdout='ext4\n')):
            with self.assertRaisesRegex(ValueError, 'memory-backed'):
                with self.start(allow_create=True):
                    self.fail('Private key was written to persistent storage')
        self.assertFalse(self.source.exists())
        self.assertTrue(self.original())

    def test_termination_signal_unwinds_the_key_context(self):
        handlers = {}
        with patch.object(access.signal, 'getsignal', return_value=signal.SIG_DFL), \
                patch.object(access.signal, 'signal', side_effect=lambda signum, handler: handlers.update({signum: handler})):
            with self.assertRaises(SystemExit) as raised:
                with self.start(allow_create=True):
                    path = access.runtime_ssh_key(self.source)
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertFalse(path.exists())
        self.assertEqual(handlers[signal.SIGTERM], signal.SIG_DFL)
        self.assertNotIn('CERTLOCKER_SSH_KEY_PATH', os.environ)

    def test_same_enrolled_key_is_seeded_into_fresh_company_trust(self):
        hosts = {f'example-{suffix}': {'ansible_host': f'192.0.2.{index}',
                  'uncloud_mesh_ip': f'10.210.{index}.1', 'uncloud_expected_hostname': f'example-{suffix}',
                  'uncloud_provider': 'supplied'} for index, suffix in enumerate(('a', 'b'), 1)}

        def ssh(path, address, command, user):
            name = next(name for name, host in hosts.items() if host['ansible_host'] == address)
            return json.dumps(dict(hostname=name, os='ubuntu', os_version='24.04',
                                   architecture='x86_64', machine_id=name))

        with self.start(allow_create=True):
            refs = access.save_host_access('example', self.trust, access.runtime_ssh_key(self.source),
                                          'ucdeploy', hosts, ssh, self.config)
            seed = access.platform_seed('example', 'Example', 'new-company-account', 'owner', refs, hosts, self.trust)
            installed = seed['secrets'][0]
            self.assertEqual(installed['account_id'], 'new-company-account')
            self.assertEqual(json.loads(installed['secret'])['key'], self.original())
            self.assertEqual(self.trust.get(refs['ssh_key_record']), self.original())
        self.assertFalse(self.source.exists())
        self.assertIn(access.provisioning_record('example'), company_trust_record_names('example'))
        directory = self.root / 'inventory'
        directory.mkdir()
        (directory / 'host-access.json').write_text(json.dumps(refs))
        (directory / 'hosts.json').write_text(json.dumps({'all': {'children': {'uncloud': {
            'hosts': hosts, 'vars': {'uncloud_trust_group': 'Example'}}}}}))
        marker = {'company': 'example', 'ssh_user': 'ucdeploy', 'ssh_key_path': str(self.source)}
        with access.installation_key('example', directory, marker) as path:
            temporary = Path(path)
            self.assertEqual(temporary.read_text(), self.original())
        self.assertFalse(temporary.exists())
        # Older installations have only the host-access record, without the new
        # pre-provisioning checkpoint. They must recover the same key as well.
        original = self.original()
        del self.trust.records[access.provisioning_record('example')]
        (self.state / 'provisioning-key.json').unlink()
        with self.start():
            self.assertEqual(access.runtime_ssh_key(self.source).read_text(), original)

    def test_standalone_setup_and_resume_keep_durable_bindings_free_of_temporary_paths(self):
        loader = importlib.machinery.SourceFileLoader('key_lifecycle_setup', str(ROOT / 'scripts/setup-ha'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        setup = importlib.util.module_from_spec(spec)
        loader.exec_module(setup)
        config = dict(self.config, operator_cidrs=['192.0.2.10/32'], vpn_cidrs=['192.0.2.10/32'],
                      certificate_mode='customer', acme_email='admin@example.com', dns_zone='example.com')
        profile = self.root / 'company.json'
        profile.write_text(json.dumps(config))
        self.source.parent.mkdir()
        self.source.write_text(access.generate_key())
        self.source.chmod(0o600)
        directory = self.root / 'inventory'
        used = []

        def run(command, **kwargs):
            path = Path(command[command.index('--private-key') + 1])
            self.assertEqual(path.read_text(), self.original())
            used.append(path)
            return ''

        with ExitStack() as patches:
            patches.enter_context(patch('uncloud_preflight.check_controller'))
            patches.enter_context(patch('uncloud_support.ensure_certlocker_token'))
            patches.enter_context(patch.object(setup, 'inventory_directory', return_value=directory))
            patches.enter_context(patch.object(setup, 'prepare_ssh'))
            patches.enter_context(patch.object(setup, 'wait_for_ssh'))
            patches.enter_context(patch.object(setup, 'run', side_effect=run))
            patches.enter_context(patch.object(setup, 'resolve_node', side_effect=lambda provider, address, name, config: {
                'ansible_host': address, 'uncloud_expected_hostname': name, 'uncloud_provider': provider}))
            args = ['example', '192.0.2.11', '192.0.2.12', 'provider_1=supplied', 'provider_2=supplied',
                    '--non-interactive', '--config', str(profile),
                    '--state-dir', str(self.state), '--until', 'harden', '--manifest-file', str(profile)]
            setup.main(args)
            first = (self.state / 'installation.json').read_text()
            self.assertFalse(self.source.exists())
            setup.main(args)
            self.assertEqual((self.state / 'installation.json').read_text(), first)
        self.assertEqual(json.loads(first)['key_path'], str(self.source))
        inventory = json.loads((directory / 'hosts.json').read_text())
        self.assertEqual(inventory['all']['children']['uncloud']['vars']['uncloud_trust_account_id'], 'customer-account')
        self.assertEqual(json.loads((directory / '.setup.json').read_text())['ssh_key_path'], str(self.source))
        self.assertNotIn('/dev/shm/', first)
        self.assertEqual(len(used), 4)
        self.assertTrue(all(not path.exists() for path in used))

    def test_nested_installation_commands_reuse_the_active_memory_key(self):
        marker = {'company': 'example', 'ssh_user': 'ucdeploy', 'ssh_key_path': str(self.source)}
        with self.start(allow_create=True):
            parent = access.runtime_ssh_key(self.source)
            with access.installation_key('example', self.root / 'missing-inventory', marker) as path:
                self.assertEqual(Path(path), parent)
            self.assertTrue(parent.exists())
        self.assertFalse(parent.exists())

    def mesh_setup(self):
        loader = importlib.machinery.SourceFileLoader('mesh_recovery_setup', str(ROOT / 'scripts/setup-ha'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_mesh_resume_rebinds_both_connections_to_new_memory_key(self):
        import yaml
        setup = self.mesh_setup()
        path = self.state / 'uncloud.yaml'
        context = 'certlocker-example'
        targets = {'ucdeploy@192.0.2.11', 'ucdeploy@192.0.2.12'}
        with self.start(allow_create=True):
            old = access.runtime_ssh_key(self.source)
            document = {'current_context': context, 'contexts': {context: {'connections': [
                {'ssh': target, 'ssh_key_file': str(old), 'machine_id': str(index)}
                for index, target in enumerate(sorted(targets))]}}}
            setup.private_write(path, yaml.safe_dump(document))
        self.assertFalse(old.exists())
        for verify_only in (False, True):
            with self.subTest(verify_only=verify_only), self.start():
                active = access.runtime_ssh_key(self.source)
                self.assertFalse(setup.prepare_uncloud_config(
                    path, context, create=not verify_only, ssh_key=active, targets=targets))
                saved = yaml.safe_load(path.read_text())
                connections = saved['contexts'][context]['connections']
                self.assertEqual({row['ssh_key_file'] for row in connections}, {str(active)})
                self.assertEqual({row['ssh'] for row in connections}, targets)
                self.assertEqual([row['machine_id'] for row in connections], ['0', '1'])
                self.assertTrue(all(Path(row['ssh_key_file']).read_text() == self.original()
                                    for row in connections))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(self.original(), path.read_text())
            self.assertFalse(active.exists())

    def test_mesh_rebinding_rejects_foreign_connections_without_writing(self):
        import yaml
        setup = self.mesh_setup()
        path = self.root / 'uncloud.yaml'
        context = 'certlocker-example'
        valid = {'ssh': 'ucdeploy@192.0.2.11', 'ssh_key_file': '/expired', 'machine_id': 'first'}
        for invalid in ({'ssh': 'other@192.0.2.12'}, dict(valid), {'tcp': 'localhost:51000'}):
            with self.subTest(invalid=invalid):
                path.write_text(yaml.safe_dump({'contexts': {context: {'connections': [valid, invalid]}}}))
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, 'differs from the intended servers'):
                    setup.prepare_uncloud_config(path, context, ssh_key='/new',
                                                 targets={'ucdeploy@192.0.2.11', 'ucdeploy@192.0.2.12'})
                self.assertEqual(path.read_bytes(), before)

    def test_mesh_missing_config_cannot_fall_back_to_local_daemon(self):
        import yaml
        setup = self.mesh_setup()
        path = self.root / 'uncloud.yaml'
        with self.assertRaisesRegex(ValueError, 'refusing local-daemon fallback'):
            setup.prepare_uncloud_config(path, 'certlocker-example', create=False)
        self.assertFalse(path.exists())
        self.assertTrue(setup.prepare_uncloud_config(path, 'certlocker-example'))
        self.assertEqual(yaml.safe_load(path.read_text()), {'contexts': {}})

    def test_workflow_finally_closes_key_on_success_failure_and_interruption(self):
        module = workflow_module()
        profile = self.root / 'company.json'
        profile.write_text(json.dumps(self.config))
        for failure in (None, RuntimeError, KeyboardInterrupt):
            with self.subTest(failure=failure), ExitStack() as patches:
                workflow = Mock()
                workflow.config = dict(self.config)
                workflow.config_path = profile
                workflow.evidence = {'cycles': []}
                workflow.started_monotonic = time.monotonic()
                workflow.ssh_keys = ExitStack()
                paths = []

                def prepare():
                    workflow.ssh_keys.enter_context(self.start(allow_create=True))
                    paths.append(access.runtime_ssh_key(self.source))

                def up(cycle):
                    if failure:
                        raise failure()
                    cycle['status'] = 'passed'

                workflow.prepare.side_effect = prepare
                workflow.up.side_effect = up
                patches.enter_context(patch.object(module, 'STATE', self.state))
                patches.enter_context(patch.object(module, 'configure'))
                patches.enter_context(patch.object(module, 'can_prompt', return_value=False))
                patches.enter_context(patch.object(module, 'Workflow', return_value=workflow))
                patches.enter_context(patch('uncloud_support.ensure_certlocker_token'))
                patches.enter_context(patch('uncloud_preflight.check_controller'))
                args = ['resume', '--config', str(profile), '--non-interactive', '--operator-cidr', '192.0.2.10/32']
                if failure:
                    with self.assertRaises(failure):
                        module.main(args)
                else:
                    module.main(args)
                self.assertEqual(len(paths), 1)
                self.assertFalse(paths[0].exists())
                self.assertFalse(self.source.exists())


if __name__ == '__main__':
    unittest.main()
