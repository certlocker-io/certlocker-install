import contextlib
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from uncloud_support import Trust, TrustAuthorizationError, ensure_certlocker_token


class TrustErrorTests(unittest.TestCase):
    def test_invalid_format_can_be_corrected_without_restarting(self):
        output = io.StringIO()
        with patch.dict(os.environ, {'TRUST_TOKEN': 'bad'}, clear=True), \
                patch('uncloud_terminal.prompt_secret', side_effect=['stillbad', 'replacement-token']) as prompt, \
                contextlib.redirect_stdout(output):
            self.assertEqual(ensure_certlocker_token(interactive=True), 'replacement-token')
            self.assertEqual(os.environ['CERTLOCKER_TOKEN'], 'replacement-token')
        self.assertEqual(prompt.call_count, 2)
        self.assertIn('Invalid Trust token format', output.getvalue())
        self.assertNotIn('stillbad', output.getvalue())
        self.assertNotIn('replacement-token', output.getvalue())

    def test_unattended_invalid_token_reports_invalid_not_missing(self):
        with patch.dict(os.environ, {'TRUST_TOKEN': 'bad'}, clear=True), \
                patch('uncloud_terminal.prompt_secret') as prompt:
            with self.assertRaisesRegex(ValueError, 'Invalid Trust token format'):
                ensure_certlocker_token()
        prompt.assert_not_called()

    def test_http_errors_are_specific_without_exposing_response_bodies(self):
        for code, body, kind, message in [
            (400, b'Invalid token', TrustAuthorizationError, 'Invalid Trust token'),
            (400, b'{"message":"Invalid token"}', TrustAuthorizationError, 'Invalid Trust token'),
            (400, b'{"message":"invalid payload: secret-value"}', RuntimeError, 'failed'),
            (401, b'secret-value', TrustAuthorizationError, 'invalid, expired or revoked'),
            (403, b'secret-value', TrustAuthorizationError, 'permission'),
            (500, b'secret-value', RuntimeError, 'failed'),
        ]:
            with self.subTest(code=code, body=body), patch('uncloud_support.urllib.request.build_opener') as opener:
                opener.return_value.open.side_effect = HTTPError('https://example.com', code, '', {}, io.BytesIO(body))
                with self.assertRaisesRegex(kind, message) as caught:
                    Trust(token='rejected-token').request('api/v1/secret/lookup?name=test')
                self.assertIs(type(caught.exception), kind)
                self.assertNotIn('secret-value', str(caught.exception))
                self.assertNotIn('rejected-token', str(caught.exception))
                opener.return_value.open.assert_called_once()

    def test_preflight_retries_rejected_token_and_updates_environment(self):
        trust = Trust(token='rejected-token')
        output = io.StringIO()
        with patch.dict(os.environ, {'CERTLOCKER_TOKEN': 'rejected-token'}, clear=True), \
                patch.object(trust, 'get', side_effect=[TrustAuthorizationError('Invalid Trust token'), None]) as get, \
                patch('uncloud_terminal.prompt_secret', return_value='replacement-token') as prompt, \
                contextlib.redirect_stdout(output):
            trust.check_authorization('example', interactive=True)
            self.assertEqual(trust.token, 'replacement-token')
            self.assertEqual(os.environ['CERTLOCKER_TOKEN'], 'replacement-token')
        self.assertEqual(get.call_count, 2)
        prompt.assert_called_once()
        self.assertIn('Invalid Trust token', output.getvalue())

    def test_unattended_auth_and_interactive_service_errors_do_not_prompt(self):
        for interactive, error in [(False, TrustAuthorizationError('Invalid Trust token')),
                                   (True, RuntimeError('Trust connection failed'))]:
            with self.subTest(interactive=interactive), \
                    patch.object(Trust, 'get', side_effect=error) as get, \
                    patch('uncloud_terminal.prompt_secret') as prompt:
                with self.assertRaises(type(error)):
                    Trust(token='test-token').check_authorization('example', interactive=interactive)
                get.assert_called_once()
                prompt.assert_not_called()


if __name__ == '__main__':
    unittest.main()
