"""Account-scoped Gateway requests used by the standalone installer."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


routes = load('gateway_routes_test', 'certlocker_gateway.py')
support = load('gateway_support_test', 'uncloud_support.py')


class GatewayAccountTests(unittest.TestCase):
    def test_transport_scopes_every_resource_and_preserves_payloads(self):
        with patch.dict(os.environ, {'CERTLOCKER_API_MODE': 'account', 'CERTLOCKER_ACCOUNT_ID': 'acct'}):
            trust = support.Trust(token='fixture-token')
            for resource, action in [('secret', 'lookup?name=fixture'), ('secret', 'fetch/fixture'),
                                     ('secret', 'create'), ('secret', 'revoke/fixture'),
                                     ('cert', 'fetch-bundle/cert-token'), ('token', 'get/token')]:
                with self.subTest(resource=resource, action=action), patch.object(support.urllib.request, 'build_opener') as opener:
                    opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{}'
                    trust.request(f'api/v1/{resource}/{action}', {'secret_type': 'PASSWORD', 'secret': 'opaque'})
                    request = opener.return_value.open.call_args.args[0]
                    self.assertEqual(request.full_url, f'https://trust.certlocker.io/rest/api/v1/{resource}/acct/{action}')
                    body = json.loads(request.data)
                    self.assertEqual(body['secret_type'], body['secretType'])
                    self.assertEqual(body['secret'], 'opaque')

    def test_missing_invalid_accounts_and_retired_modes_are_rejected(self):
        for mode, account in [('account', ''), ('invalid', 'acct'), ('account', '../other'),
                              ('legacy', 'acct'), ('auto', 'acct')]:
            with self.subTest(mode=mode, account=account), self.assertRaises(ValueError):
                routes.GatewayRoutes(account, mode)

    def test_default_account_and_explicit_override(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(routes.GatewayRoutes().account_id, '2pc4im00jo')
            self.assertEqual(routes.GatewayRoutes('customer').account_id, 'customer')

    def test_scoped_routes_and_oidc_exchange_are_preserved(self):
        route = routes.GatewayRoutes('acct', 'account')
        self.assertEqual(route.path('api/v1/secret/acct/get/one'), 'api/v1/secret/acct/get/one')
        self.assertEqual(route.path('api/v1/oidc/exchange'), 'api/v1/oidc/exchange')
        with self.assertRaises(ValueError):
            route.path('api/v1/secret/other/get/one')


if __name__ == '__main__':
    unittest.main()
