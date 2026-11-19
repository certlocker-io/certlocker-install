"""Exercise setup's stage runner without provisioning remote machines."""
import ast
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from uncloud_support import MISSING, resolve_environment, trust_name


class SetupTrustSnapshotTests(unittest.TestCase):
    def stage_runner(self):
        # Compile the real nested runner with its enclosing state supplied by
        # this fixture, so no SSH, provisioning, or live Trust access is needed.
        source = ast.parse((ROOT / 'scripts/setup-ha').read_text())
        runner = next(node for node in ast.walk(source)
                      if isinstance(node, ast.FunctionDef) and node.name == 'execute_play')
        trust = Mock()
        records = {trust_name('example', 'password'): 'original-password'}
        trust.get.side_effect = lambda name: records.get(name, MISSING)
        state = dict(ROOT=ROOT, company_dir=Path('/inventory/example'), key='/memory/key',
                     company='example', trust=trust, variables=['password'],
                     runtime_values={}, registry_mode='ghcr',
                     resolve_environment=resolve_environment, run_ansible=Mock(), run=Mock())
        exec(compile(ast.Module(body=[runner], type_ignores=[]), '<setup runner>', 'exec'), state)
        return state, records

    def test_database_stage_loads_identity_added_after_network_stage(self):
        state, records = self.stage_runner()
        snapshots = []
        state['run_ansible'].side_effect = lambda command, values, **kwargs: snapshots.append(dict(values))
        state['execute_play']('uncloud_apps_network.yml')
        self.assertEqual(snapshots, [{'password': 'original-password'}])

        identity = {'nodes': {'example-a': {}, 'example-b': {}}, 'passwords': {}}
        variable = 'vault_certlocker_database_identity'
        records[trust_name('example', variable)] = identity
        state['variables'].append(variable)
        state['execute_play']('uncloud_database.yml')
        self.assertEqual(snapshots[-1], {'password': 'original-password', variable: identity})
        state['execute_play']('uncloud_database_verify.yml')
        self.assertEqual(snapshots[-1], snapshots[-2])
        self.assertEqual(state['trust'].get.call_count, 2)

    def test_missing_later_record_stops_before_running_database_playbook(self):
        state, _ = self.stage_runner()
        state['execute_play']('uncloud_apps_network.yml')
        state['variables'].append('vault_certlocker_database_identity')
        with self.assertRaisesRegex(ValueError, 'Required company Trust record is missing'):
            state['execute_play']('uncloud_database.yml')
        self.assertEqual(state['run_ansible'].call_count, 1)

    def test_runtime_overrides_are_preserved_when_new_records_are_loaded(self):
        state, records = self.stage_runner()
        state['execute_play']('uncloud_apps_network.yml')
        state['runtime_values']['uncloud_ingress_pem'] = 'runtime-certificate'
        state['runtime_values']['password'] = 'validated-override'
        records[trust_name('example', 'later')] = 'later-value'
        state['variables'].append('later')
        state['execute_play']('uncloud_database.yml')
        self.assertEqual(state['runtime_values'], {
            'password': 'validated-override', 'uncloud_ingress_pem': 'runtime-certificate',
            'later': 'later-value'})


if __name__ == '__main__':
    unittest.main()
