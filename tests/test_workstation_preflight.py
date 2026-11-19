import contextlib
import io
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError


MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/prepare-ha-workstation'))


class WorkstationPermissionsTests(unittest.TestCase):
    def check(self, outcomes):
        opener = Mock()
        opener.open.side_effect = outcomes
        self.opener = opener
        with patch('subprocess.run', return_value=Mock(returncode=0, stdout='private-token')), \
                patch('urllib.request.build_opener', return_value=opener), \
                patch('time.sleep') as sleep, contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.sleep = sleep
            self.stderr = stderr
            return MODULE['project_permissions']('gcloud', 'example-project', ('compute.instances.create',))

    def error(self, code):
        return HTTPError('https://cloudresourcemanager.googleapis.com/', code,
                         'private-token', {}, io.BytesIO(b'private-token'))

    def response(self, permissions):
        return io.StringIO(json.dumps({'permissions': permissions}))

    def test_temporary_failure_retries_and_succeeds(self):
        for status in (429, 500, 502, 503, 504):
            with self.subTest(status=status):
                result = self.check([self.error(status), self.response(['compute.instances.create'])])
                self.assertEqual(result, ['compute.instances.create'])
                self.assertEqual(self.opener.open.call_count, 2)
                self.sleep.assert_called_once_with(1)
                self.assertIn(f'HTTP {status}', self.stderr.getvalue())
                self.assertNotIn('private-token', self.stderr.getvalue())

    def test_retries_are_bounded_and_error_is_safe(self):
        with self.assertRaisesRegex(RuntimeError, 'testIamPermissions.*example-project: HTTP 503') as caught:
            self.check([self.error(503) for _ in range(3)])
        self.assertEqual(self.opener.open.call_count, 3)
        self.assertEqual(self.sleep.call_count, 2)
        self.assertNotIn('private-token', str(caught.exception))

    def test_authentication_and_access_errors_fail_without_retry(self):
        for status, hint in ((401, 'gcloud auth login'), (403, 'project access'), (404, 'project ID')):
            with self.subTest(status=status):
                with self.assertRaisesRegex(RuntimeError, f'HTTP {status}.*{hint}') as caught:
                    self.check([self.error(status)])
                self.assertEqual(self.opener.open.call_count, 1)
                self.sleep.assert_not_called()
                self.assertNotIn('private-token', str(caught.exception))

    def test_missing_permissions_still_block_setup(self):
        with self.assertRaisesRegex(ValueError, 'lacks required project permissions: compute.instances.create'):
            self.check([self.response([])])
        self.assertEqual(self.opener.open.call_count, 1)
        self.sleep.assert_not_called()
