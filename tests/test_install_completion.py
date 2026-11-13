import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import uncloud_certificates as certificates
import uncloud_enrollment as enrollment
import uncloud_install_notification as notifications
from uncloud_support import MISSING, trust_name

TOKEN = 'example-test-token'
ZONE_ID = 'a' * 32
# Deliberately fake values, assembled to avoid resembling a shipped credential.
WEBHOOK = 'https://chat.googleapis.com/v1/spaces/test-space/messages?' + 'key=example&token=example'


def response(result):
    return io.StringIO(json.dumps({'success': True, 'result': result}))


def api_error(status, code=9109):
    return urllib.error.HTTPError('https://api.cloudflare.com/', status, 'private', {},
        io.BytesIO(json.dumps({'errors': [{'code': code, 'message': TOKEN}]}).encode()))


class CloudflareTests(unittest.TestCase):
    def test_teardown_fallback_is_validated_and_never_overrides_a_saved_token(self):
        for saved, expected in ((MISSING, TOKEN), ('', TOKEN), ('saved-test-token', 'saved-test-token')):
            with self.subTest(saved=saved), patch.object(certificates.urllib.request, 'build_opener') as opener:
                trust = Mock()
                trust.get.return_value = saved
                opener.return_value.open.side_effect = [
                    response([{'id': ZONE_ID, 'name': 'example.com', 'status': 'active'}]),
                    response([]), response({'status': 'active'})]
                result = certificates.cloudflare_preflight('example', trust, 'example.com', fallback_token=TOKEN)
                self.assertEqual(result, (expected, ZONE_ID))
                for call in opener.return_value.open.call_args_list:
                    self.assertEqual(call.args[0].get_header('Authorization'), 'Bearer ' + expected)
                trust.ensure.assert_not_called()

    def test_missing_teardown_credential_still_requires_a_valid_operator_token(self):
        trust = Mock()
        trust.get.return_value = MISSING
        with patch.object(certificates.urllib.request, 'build_opener') as opener:
            with self.assertRaises(certificates.CloudflareCredentialError):
                certificates.cloudflare_preflight('example', trust, 'example.com')
            opener.assert_not_called()
            opener.return_value.open.side_effect = api_error(403)
            with self.assertRaises(certificates.CloudflareCredentialError):
                certificates.cloudflare_preflight('example', trust, 'example.com', fallback_token=TOKEN)

    def test_rejection_has_status_code_zone_and_no_reflected_token(self):
        trust = Mock()
        trust.get.return_value = TOKEN
        for status, code in ((401, 9109), (403, 10000), (400, 6003)):
            with self.subTest(status=status), patch.object(certificates.urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = api_error(status, code)
                with self.assertRaises(certificates.CloudflareCredentialError) as caught:
                    certificates.cloudflare_preflight('example', trust, 'example.com')
                self.assertIn('HTTP ' + str(status), str(caught.exception))
                self.assertIn('code ' + str(code), str(caught.exception))
                self.assertIn('example.com', str(caught.exception))
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_verify_network_error_does_not_blame_account_token(self):
        trust = Mock()
        trust.get.return_value = TOKEN
        with patch.object(certificates.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = [
                response([{'id': ZONE_ID, 'name': 'example.com', 'status': 'active'}]),
                response([]), OSError(TOKEN)]
            with self.assertRaises(RuntimeError) as caught:
                certificates.cloudflare_preflight('example', trust, 'example.com')
        self.assertNotIsInstance(caught.exception, certificates.CloudflareCredentialError)
        self.assertIn('same token', str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_rate_limit_and_server_error_are_not_credential_rejections(self):
        trust = Mock()
        trust.get.return_value = TOKEN
        for status in (429, 503):
            with self.subTest(status=status), patch.object(certificates.urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = api_error(status, 0)
                with self.assertRaises(RuntimeError) as caught:
                    certificates.cloudflare_preflight('example', trust, 'example.com')
                self.assertNotIsInstance(caught.exception, certificates.CloudflareCredentialError)
                self.assertIn('same token', str(caught.exception))

    def enroll(self, existing, checks, prompts=(), interactive=True, supplied=''):
        trust = Mock(group='Example')
        trust.get.side_effect = [MISSING, existing]
        trust.ensure.side_effect = lambda company, name, factory: factory()
        with patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': supplied}), \
                patch.object(enrollment, 'can_prompt', return_value=interactive), \
                patch.object(enrollment, 'prompt_secret', side_effect=prompts) as prompt, \
                patch.object(enrollment, 'cloudflare_preflight', side_effect=checks), \
                patch.object(enrollment, 'replace_rejected_cloudflare_token') as replace, \
                contextlib.redirect_stdout(io.StringIO()):
            result = enrollment.enroll('example', trust, {'certificate_mode': 'customer',
                'dns_zone': 'example.com', 'acme_email': 'admin@example.com'}, non_interactive=not interactive)
        return trust, prompt, replace, result

    def test_rejected_new_token_reprompts_before_storing(self):
        trust, prompt, replace, result = self.enroll(MISSING,
            [certificates.CloudflareCredentialError('Invalid token'), (TOKEN, ZONE_ID), (TOKEN, ZONE_ID)],
            ['bad-test-token', TOKEN])
        self.assertEqual(prompt.call_count, 2)
        trust.populate_empty.assert_called_once_with('example', 'vault_cloudflare_ini_key', TOKEN)
        replace.assert_not_called()
        self.assertEqual(result['zone_id'], ZONE_ID)

    def test_rejected_saved_token_can_be_replaced_after_validation(self):
        trust, prompt, replace, _ = self.enroll('old-test-token',
            [certificates.CloudflareCredentialError('Expired token'), (TOKEN, ZONE_ID), (TOKEN, ZONE_ID)],
            [TOKEN])
        replace.assert_called_once_with('example', trust, 'old-test-token', TOKEN)
        trust.populate_empty.assert_not_called()

    def test_valid_saved_token_is_not_rotated_by_environment(self):
        trust, prompt, replace, _ = self.enroll(TOKEN, [(TOKEN, ZONE_ID)], supplied='other-token')
        prompt.assert_not_called()
        replace.assert_not_called()
        trust.populate_empty.assert_not_called()

    def test_unattended_replacement_validated_before_write(self):
        trust, prompt, replace, _ = self.enroll('old-test-token',
            [certificates.CloudflareCredentialError('Expired token'), (TOKEN, ZONE_ID), (TOKEN, ZONE_ID)],
            interactive=False, supplied=TOKEN)
        prompt.assert_not_called()
        replace.assert_called_once_with('example', trust, 'old-test-token', TOKEN)

    def test_transient_failure_does_not_prompt_for_or_replace_token(self):
        with self.assertRaisesRegex(RuntimeError, 'network'):
            self.enroll(TOKEN, [RuntimeError('network unavailable')])

    def test_replacement_refuses_changed_record_without_revocation(self):
        trust = Mock(group='Example')
        trust.request.side_effect = [
            {'id': 'record', 'name': trust_name('example', 'vault_cloudflare_ini_key'), 'groups': ['Example']},
            json.dumps({'value': 'concurrent-token'})]
        with self.assertRaisesRegex(ValueError, 'concurrently'):
            enrollment.replace_rejected_cloudflare_token('example', trust, 'old-token', TOKEN)
        self.assertEqual(trust.request.call_count, 2)
        trust.ensure.assert_not_called()


class WorkflowNotificationTests(unittest.TestCase):
    def test_notification_follows_all_workflow_checks(self):
        from test_guided_install import workflow_module, company_config
        for failure in (None, 'verification', 'database', 'ip_lookup', 'archive'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
                module = workflow_module()
                config = company_config()
                state = Path(temp)
                nodes = {name: {'public_ip': address, 'private_ip': private,
                         'zone': config['nodes'][name]['zone'], 'status': 'RUNNING', 'instance_id': str(index)}
                         for index, (name, address, private) in enumerate([
                             ('example-a', '192.0.2.10', '10.44.10.10'),
                             ('example-b', '192.0.2.20', '10.44.20.10')])}
                for key, value in [('STATE', state), ('NAMES', tuple(nodes)), ('COMPANY', 'example'),
                                   ('MACHINE_NAMES', {name: name for name in nodes}), ('TRUST_GROUP', 'Example'),
                                   ('ZONES', {name: node['zone'] for name, node in nodes.items()}),
                                   ('DNS_ZONE', 'example.com'),
                                   ('LAB_NAMES', ('certlocker.example.com', 'backoffice.example.com'))]:
                    stack.enter_context(patch.object(module, key, value))
                inventory = state / 'inventory'
                inventory.mkdir()
                (inventory / 'release.json').write_text(json.dumps({'release': 'prod_1.1.28'}))
                stack.enter_context(patch('uncloud_support.inventory_directory', return_value=inventory))
                trust = Mock()
                trust.get.return_value = {'hostname': 'certlocker.example.com',
                                         'backoffice_hostname': 'backoffice.example.com',
                                         'grafana_hostname': 'grafana.example.com'}
                stack.enter_context(patch('uncloud_support.Trust', return_value=trust))
                stack.enter_context(patch('uncloud_certificates.cloudflare_preflight', return_value=(TOKEN, ZONE_ID)))
                stack.enter_context(patch('uncloud_cloudflare.Cloudflare'))
                stack.enter_context(patch('uncloud_cloudflare.check_access', return_value='b' * 32))
                stack.enter_context(patch('uncloud_cloudflare.plan', return_value={}))
                stack.enter_context(patch('uncloud_cloudflare.verify', return_value={'configuration_and_both_origins': 'passed'}))
                stack.enter_context(patch('uncloud_dns.remove_owned', return_value=[]))
                connection = stack.enter_context(patch.object(module.socket, 'create_connection'))
                if failure != 'database':
                    connection.side_effect = OSError('closed')
                collect = stack.enter_context(patch('uncloud_install_receipt.collect_public_ips',
                    side_effect=RuntimeError('IP unavailable') if failure == 'ip_lookup' else None))
                archive = stack.enter_context(patch('uncloud_install_receipt.archive_installation',
                    return_value={'status': 'saved', 'installation_record': 'example-record'},
                    side_effect=RuntimeError('Trust unavailable') if failure == 'archive' else None))
                notify = stack.enter_context(patch.object(notifications, 'notify_installation', return_value={'status': 'sent'}))
                workflow = module.Workflow.__new__(module.Workflow)
                workflow.progress = Mock()
                workflow.progress.stage.side_effect = lambda label: contextlib.nullcontext()
                workflow.config_path = state / 'company.json'
                workflow.action = 'up'
                workflow.config = config
                workflow.until = 'apps'
                workflow.machine_type = 'e2-standard-2'
                workflow.boot_disk_size_gb = 100
                workflow.skip_failover = True
                workflow.apply = Mock(return_value={'create': 2})
                workflow.tf = Mock(return_value=json.dumps(nodes))
                workflow.save = Mock()

                def command(args):
                    if '--verify-only' in args and failure == 'verification':
                        raise RuntimeError('verification failed')
                    directory = Path(args[args.index('--state-dir') + 1])
                    for name in ('timings-setup.json', 'timings-verify.json', 'certificate-bootstrap.json'):
                        (directory / name).write_text('{}')

                workflow.command = command
                cycle = {}
                if failure:
                    with self.assertRaises((ValueError, RuntimeError)):
                        workflow.up(cycle)
                    notify.assert_not_called()
                else:
                    workflow.up(cycle)
                    notify.assert_called_once()
                    collect.assert_called_once()
                    archive.assert_called_once()
                    self.assertTrue(cycle['verify_passed'])
                    self.assertTrue(cycle['public_database_closed'])
                    self.assertEqual(cycle['installation_notification']['status'], 'sent')


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {'deployment': 'prod', 'google_project': 'example-project',
                       'front_url': 'https://app.example.com', 'secret': 'must-not-appear'}
        self.cycle = {'status': 'passed', 'verified_through': 'apps', 'install_passed': True,
                      'verify_passed': True, 'public_database_closed': True, 'generation': 'generation-a',
                      'final_release': {'release': 'prod_1.1.28'}, 'state_dir': self.temp.name,
                      'installation_trust': {'status': 'saved', 'installation_record': 'example-install-record',
                                             'operator': {'status': 'saved'},
                                             'customer': {'status': 'saved', 'record_name': 'example installer JSON'}},
                      'nodes': {name: {'public_ip': address, 'private_ip': private, 'zone': zone,
                          'instance_id': str(index), 'status': 'RUNNING', 'reported_public_ip': '8.8.8.' + str(index + 1), 'secret': 'must-not-appear'}
                          for index, (name, address, private, zone) in enumerate([
                              ('example-a', '192.0.2.10', '10.0.0.1', 'zone-a'),
                              ('example-b', '192.0.2.20', '10.0.0.2', 'zone-b')])}}

    def notify(self):
        return notifications.notify_installation('example', self.config, self.cycle, {}, 'e2-standard-2', 100)

    def test_only_verified_full_installations_are_announced(self):
        for key, bad in [('status', 'failed'), ('verified_through', 'database'), ('verify_passed', False),
                         ('install_passed', False), ('public_database_closed', False), ('installation_trust', {}),
                         ('installation_trust', {'status': 'saved', 'operator': {'status': 'saved'}})]:
            with self.subTest(key=key), patch.dict(self.cycle, {key: bad}), \
                    patch.object(notifications, 'webhook') as webhook:
                self.assertEqual(self.notify()['status'], 'not_sent')
                webhook.assert_not_called()

    def test_message_has_both_servers_and_no_arbitrary_config_or_credentials(self):
        with patch.object(notifications, 'webhook', return_value=WEBHOOK), \
                patch.object(notifications, 'post') as post:
            self.assertEqual(self.notify()['status'], 'sent')
            text = post.call_args.args[1]
            for value in ('8.8.8.1', '8.8.8.2', '10.0.0.1', '10.0.0.2', 'zone-a', 'zone-b',
                          'e2-standard-2', '100 GiB', 'prod_1.1.28', 'https://app.example.com'):
                self.assertIn(value, text)
            self.assertNotIn('192.0.2.10', text)
            self.assertNotIn('192.0.2.20', text)
            self.assertIn('example-install-record', text)
            self.assertNotIn('must-not-appear', text)
            self.assertNotIn(WEBHOOK, text)
            self.assertTrue(self.notify()['already_sent'])
            post.assert_called_once()
        marker = Path(self.temp.name) / 'install-chat.json'
        self.assertNotIn(WEBHOOK, marker.read_text())
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_delivery_failure_preserves_installation_and_resume_retries_same_message(self):
        with patch.object(notifications, 'webhook', return_value=WEBHOOK), \
                patch.object(notifications, 'post', side_effect=[RuntimeError(WEBHOOK), None]) as post, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.notify()['status'], 'unconfirmed')
            self.assertEqual(self.cycle['status'], 'passed')
            self.assertEqual(self.notify()['status'], 'sent')
        self.assertNotIn(WEBHOOK, output.getvalue())
        self.assertEqual(post.call_args_list[0].args, post.call_args_list[1].args)

    def test_webhook_rejects_redirect_hosts_and_missing_credentials(self):
        trust = Mock()
        with patch.object(notifications, 'Trust', return_value=trust):
            for url in ('https://example.com/v1/spaces/test/messages?' + 'key=a&token=b',
                        'http://chat.googleapis.com/v1/spaces/test/messages?' + 'key=a&token=b',
                        'https://chat.googleapis.com/v1/spaces/test/messages?' + 'key=a'):
                trust.get.return_value = url
                with self.assertRaises(ValueError):
                    notifications.webhook(self.config)

    def test_delivery_requires_exact_response_and_uses_supported_webhook_request(self):
        with patch.object(notifications.urllib.request, 'build_opener') as opener:
            reply = Mock(status=200)
            reply.read.return_value = json.dumps({'text': 'Installed', 'name': 'spaces/test/messages/id'}).encode()
            opener.return_value.open.return_value.__enter__.return_value = reply
            notifications.post(WEBHOOK, 'Installed')
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, WEBHOOK)
            self.assertNotIn('requestId', request.full_url)
            self.assertEqual(json.loads(request.data), {'text': 'Installed'})
            reply.read.return_value = json.dumps({'text': 'Wrong', 'name': 'spaces/test/messages/id'}).encode()
            with self.assertRaisesRegex(RuntimeError, 'exact installation message'):
                notifications.post(WEBHOOK, 'Installed')


if __name__ == '__main__':
    unittest.main()
