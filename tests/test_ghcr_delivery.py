from email.message import Message
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from uncloud_support import (
    DEFAULT_GHCR_SECRET_NAME, MISSING, bundled_release_manifest, ensure_certlocker_token,
    initialize_environment, trust_name, validate_release_manifest,
)


class GhcrDeliveryTests(unittest.TestCase):
    def test_bundled_production_release_is_ready_for_ghcr(self):
        manifest, _ = bundled_release_manifest(ROOT / 'releases/current.json')
        self.assertEqual(manifest['release'], 'prod_1.1.30')
        self.assertEqual(len(manifest['services']), 8)
        self.assertEqual({item['version'] for item in manifest['services'].values()},
                         {'prod_1.1.30'})
        self.assertTrue(all(item['image'].startswith('ghcr.io/certlocker-io/')
                            for item in manifest['services'].values()))

    def test_local_pull_token_requires_exact_read_scope_before_trust_enrollment(self):
        from uncloud_install_setup import HOSTED_GATEWAY, enroll_registry_file
        config = dict(install_config_id='config-id', trust_group='customer', trust_account_id='account')
        trust = Mock(api_url=HOSTED_GATEWAY, group='customer')
        trust.routes.account_id = 'account'
        sample = 'ghp_' + 'sample'
        trust.populate_empty.return_value = sample
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'token'
            path.write_text(sample + '\n')
            path.chmod(0o600)
            for scopes in ['repo, read:packages', 'read:packages, write:packages', '', 'read:packages']:
                response = io.BytesIO(b'{"login":"package-reader"}')
                response.headers = Message()
                response.headers['X-OAuth-Scopes'] = scopes
                with self.subTest(scopes=scopes), patch('urllib.request.build_opener') as build:
                    build.return_value.open.return_value = response
                    if scopes == 'read:packages':
                        enroll_registry_file('example', trust, config, path)
                        trust.populate_empty.assert_called_once_with('example', 'vault_cr_pat', sample)
                        self.assertEqual(config['ghcr_username'], 'package-reader')
                        self.assertNotIn(sample, json.dumps(config))
                    else:
                        with self.assertRaisesRegex(ValueError, 'exactly the read:packages'):
                            enroll_registry_file('example', trust, config, path)
                        trust.populate_empty.assert_not_called()
                    self.assertEqual(build.return_value.open.call_args.args[0].full_url,
                                     'https://api.github.com/user')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'owner-only'):
                enroll_registry_file('example', trust, config, path)

    def test_controller_mounts_external_ghcr_token_file_readonly(self):
        from controller_runtime import container_arguments
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / 'token'
            path.touch(mode=0o600)
            with patch('controller_runtime.Path.home', return_value=home):
                args = container_arguments('uncloud', ['up', '--ghcr-token-file', str(path)], 'controller')
            target = args[args.index('--ghcr-token-file') + 1]
            self.assertIn('type=bind,source=' + str(path) + ',target=' + target + ',readonly', args)

    def test_manifest_rejects_credentials_and_mutable_images(self):
        manifest = json.loads((ROOT / 'releases/current.json').read_text())
        manifest['TRUST_TOKEN'] = 'example-only'
        with self.assertRaises(ValueError):
            validate_release_manifest(manifest)
        manifest.pop('TRUST_TOKEN')
        manifest['services']['router']['image'] = 'ghcr.io/certlocker-io/trust/certlocker-router:latest'
        with self.assertRaises(ValueError):
            validate_release_manifest(manifest)

    def test_missing_token_prompts_with_hidden_input(self):
        with patch.dict(os.environ, {}, clear=True), patch('uncloud_terminal.prompt_secret', return_value='test-deployment-token') as prompt:
            self.assertEqual(ensure_certlocker_token(interactive=True), 'test-deployment-token')
            self.assertEqual(os.environ['CERTLOCKER_TOKEN'], 'test-deployment-token')
        prompt.assert_called_once()

    def test_trust_token_environment_alias_skips_prompt(self):
        with patch.dict(os.environ, {'TRUST_TOKEN': 'test-deployment-token'}, clear=True), patch('uncloud_terminal.prompt_secret') as prompt:
            self.assertEqual(ensure_certlocker_token(), 'test-deployment-token')
            self.assertEqual(os.environ['CERTLOCKER_TOKEN'], 'test-deployment-token')
        prompt.assert_not_called()

    def test_ghcr_credential_is_fetched_from_authorized_trust_record(self):
        source = 'example-registry-credential'
        trust = Mock()
        trust.get.side_effect = lambda name: ({'ghcr_username': 'example-user'}
            if name == trust_name('example', 'vault_certlocker_application_settings')
            else 'example-pull-credential' if name == source else MISSING)
        trust.ensure.side_effect = lambda company, name, factory, allow_create: factory()
        with patch('uncloud_support.prepare_trust', return_value=[]):
            variables = initialize_environment('example', trust, registry_mode='ghcr', ghcr_secret_name=source)
        self.assertIn('vault_cr_pat', variables)
        trust.get.assert_any_call(source)
        # Integration webhooks and other shared credentials are not fetched.
        self.assertEqual({call.args[0] for call in trust.get.call_args_list}, {
            source, trust_name('example', 'vault_certlocker_application_settings'),
            trust_name('example', 'vault_cr_pat'),
            trust_name('example', 'vault_certlocker_repmgr_password')})

    def test_default_registry_record_needs_no_customer_override(self):
        trust = Mock()
        trust.get.side_effect = lambda name: ({'ghcr_username': 'example-user'}
            if name == trust_name('example', 'vault_certlocker_application_settings')
            else 'example-pull-credential' if name == DEFAULT_GHCR_SECRET_NAME else MISSING)
        trust.ensure.side_effect = lambda company, name, factory, allow_create: factory()
        with patch.dict(os.environ, {}, clear=True), patch('uncloud_support.prepare_trust', return_value=[]):
            self.assertIn('vault_cr_pat', initialize_environment('example', trust))
        trust.get.assert_any_call(DEFAULT_GHCR_SECRET_NAME)

    def test_config_image_access_does_not_create_a_second_registry_secret(self):
        trust = Mock()
        trust.get.return_value = {'ghcr_username': 'release-reader'}
        with patch('uncloud_support.prepare_trust', return_value=[]):
            variables = initialize_environment('example', trust, config_image_access=True)
        self.assertIn('vault_cr_pat', variables)
        self.assertNotIn('vault_cr_pat', [call.args[1] for call in trust.ensure.call_args_list])

    def test_missing_ghcr_credential_fails_without_fallback_or_value_in_error(self):
        trust = Mock()
        trust.get.side_effect = lambda name: ({'ghcr_username': 'example-user'}
            if name == trust_name('example', 'vault_certlocker_application_settings') else MISSING)
        trust.ensure.side_effect = lambda company, name, factory, allow_create: factory()
        with patch('uncloud_support.prepare_trust', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'GHCR pull credential is missing or empty'):
                initialize_environment('example', trust, registry_mode='ghcr', ghcr_secret_name='example-registry-credential')


if __name__ == '__main__':
    unittest.main()
