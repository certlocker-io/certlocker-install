"""Token-discovered destinations, with an in-memory Gateway transport."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote, urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from uncloud_support import Trust, MISSING, registry_pull_credential, trust_name


class Gateway:
    def __init__(self, **metadata):
        self.metadata = dict(id='install-token', accountId='acct', tokenType='SECRET',
                             groupAccess=['Install 42'], groups=['Token administration'],
                             singleUse=False, autoRotate=False)
        self.metadata.update(metadata)
        self.records = {}
        self.requests = []

    def open(self, request, **kwargs):
        path = urlsplit(request.full_url).path.removeprefix('/gateway')
        self.requests.append(request)
        if path.startswith('/rest/api/v1/token/acct/get/'):
            result = self.metadata
        elif path == '/rest/api/v1/secret/acct/create':
            record = json.loads(request.data)
            record['id'] = str(len(self.records) + 1)
            self.records[record['name']] = record
            result = record
        elif path == '/rest/api/v1/secret/acct/lookup':
            name = parse_qs(urlsplit(request.full_url).query)['name'][0]
            result = self.records.get(name)
        elif path.startswith('/rest/api/v1/secret/acct/fetch/'):
            identifier = unquote(path.rsplit('/', 1)[1])
            record = next(row for row in self.records.values() if row['id'] == identifier)
            result = json.loads(record['secret'])
        else:
            raise AssertionError('Unexpected fixture request')
        return io.BytesIO(json.dumps(result).encode())

    def connect(self):
        return patch('uncloud_support.urllib.request.build_opener', return_value=self)


class InstallationTokenGroupTests(unittest.TestCase):
    def trust(self, **kwargs):
        return Trust(token='install-token', account_id='acct', **kwargs)

    def test_new_install_discovers_access_group_and_writes_all_record_types_there(self):
        gateway = Gateway()
        with gateway.connect():
            trust = self.trust()
            self.assertEqual(trust.check_authorization('unrelated-company'), 'Install 42')
            for name, value, kind in [('database', 'fixture-password', 'CONFIGURATION'),
                                      ('ssh-key', 'fixture-private-key', 'PEM'),
                                      ('installation-json', {'generation': 1}, 'CONFIGURATION')]:
                self.assertEqual(trust.ensure_named(name, 'unrelated-company', lambda: value,
                                                   secret_type=kind), value)
                self.assertEqual(gateway.records[name]['groups'], ['Install 42'])
                self.assertEqual(trust.get(name), value)
        # Metadata is fetched once per client/token, not once per record.
        self.assertEqual(sum('/token/' in row.full_url for row in gateway.requests), 1)
        self.assertEqual(gateway.requests[0].get_header('X-api-token'), 'install-token')
        self.assertEqual(gateway.requests[0].full_url,
                         'https://trust.certlocker.io/rest/api/v1/token/acct/get/install-token')

    def test_ambiguous_unrestricted_and_malformed_groups_stop_before_secret_access(self):
        for groups in (None, [], ['one', 'two'], ['one', 'one'], '*', ['*'], [''], [None], ['../other']):
            gateway = Gateway(groupAccess=groups, groups=['Wrong fallback'])
            with self.subTest(groups=groups), gateway.connect():
                factory = Mock(return_value='must-not-be-written')
                with self.assertRaisesRegex(ValueError, 'exactly one Trust group'):
                    self.trust().ensure_named('key', 'company', factory)
                factory.assert_not_called()
                self.assertEqual(len(gateway.requests), 1)
                self.assertFalse(gateway.records)

    def test_unusable_tokens_and_wrong_metadata_fail_without_exposing_the_token(self):
        for override in ({'id': 'other-token'}, {'accountId': 'another-account'},
                         {'tokenType': 'ROOT'}, {'singleUse': True}, {'autoRotate': True},
                         {'secretId': 'one-secret'}):
            gateway = Gateway(**override)
            with self.subTest(override=override), gateway.connect():
                with self.assertRaises(ValueError) as error:
                    self.trust().get('installation-secret')
                self.assertNotIn('install-token', str(error.exception))
                self.assertEqual(len(gateway.requests), 1)

    def test_saved_group_rejects_a_different_install_before_reads_or_writes(self):
        gateway = Gateway(groupAccess=['Install 99'])
        with gateway.connect(), self.assertRaisesRegex(ValueError, 'differs from the saved'):
            self.trust(group='Install 42').ensure_named('key', 'company', lambda: 'fixture')
        self.assertEqual(len(gateway.requests), 1)

    def test_same_group_replacement_token_is_supported_but_other_group_is_rejected(self):
        gateway = Gateway()
        trust = self.trust(group='Install 42')
        with gateway.connect():
            trust.resolve_install_group()
            trust.token = 'replacement-token'
            gateway.metadata['id'] = trust.token
            self.assertEqual(trust.resolve_install_group(), 'Install 42')
            trust.token = 'another-token'
            gateway.metadata.update(id=trust.token, groupAccess=['Install 99'])
            with self.assertRaisesRegex(ValueError, 'differs from the saved'):
                trust.get('key')
        self.assertEqual(len(gateway.requests), 3)

    def test_create_cannot_override_discovered_group(self):
        for groups in (None, [], ['Other'], ['Install 42', 'Other']):
            gateway = Gateway()
            with self.subTest(groups=groups), gateway.connect():
                with self.assertRaisesRegex(ValueError, 'only in the token group'):
                    self.trust().request('api/v1/secret/create', {'groups': groups})
                self.assertEqual(len(gateway.requests), 1)

    def test_outside_group_lookup_is_not_fetched_or_revoked(self):
        for action in ('get', 'revoke_named'):
            gateway = Gateway()
            gateway.records['foreign'] = dict(id='foreign-id', name='foreign', groups=['Other'],
                                               secret=json.dumps({'value': 'private'}))
            with self.subTest(action=action), gateway.connect():
                with self.assertRaisesRegex(ValueError, 'outside the installation token group'):
                    getattr(self.trust(), action)('foreign')
                self.assertEqual(len(gateway.requests), 2)

    def test_provisioned_install_registry_credential_needs_no_shared_secret_access(self):
        trust = Mock()
        trust.get.side_effect = lambda name: 'fixture-pull-token' if name == trust_name('company', 'vault_cr_pat') else MISSING
        self.assertEqual(registry_pull_credential('company', trust), 'fixture-pull-token')
        trust.get.assert_called_once_with(trust_name('company', 'vault_cr_pat'))


if __name__ == '__main__':
    unittest.main()
