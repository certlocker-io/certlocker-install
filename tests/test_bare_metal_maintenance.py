"""Exercise the shipped update entry point and bare-metal completion receipt."""
from contextlib import nullcontext
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import uncloud_install_notification as notifications


def update_module():
    loader = importlib.machinery.SourceFileLoader('test_update_entrypoint', str(SCRIPTS / 'update-installation'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


class MaintenanceTests(unittest.TestCase):
    def test_drain_timeout_blocks_container_replacement(self):
        path = SCRIPTS.parent / 'playbooks/ops/files/uncloud_ingress_control.py'
        spec = importlib.util.spec_from_file_location('ingress_control', path)
        ingress = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ingress)
        with patch.object(ingress, 'current_sessions', return_value=1), patch.object(
                ingress.time, 'monotonic', side_effect=[0, 1, 16]), patch.object(ingress.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'Active requests remain'):
                ingress.wait_drained('socket', 'node')

    def test_update_checks_manifest_and_records_release_after_verification(self):
        module = update_module()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest, _ = module.bundled_release_manifest(module.ROOT / 'releases/current.json')
            old = json.loads(json.dumps(manifest))
            old['release'] = 'prod_0.0.1'
            old['services']['ui']['image'] = old['services']['ui']['image'].split('@')[0] + '@sha256:' + '0'*64
            def save(name, obj):
                (directory / name).write_text(json.dumps(obj))
            save('.setup.json', {'company':'demo', 'state_dir':tmp, 'ssh_user':'ubuntu'})
            save('installation.json', {'config':{'registry_mode':'gcp'}})
            save('hosts.json', {'all':{'children':{'uncloud':{'hosts':{}}}}})
            save('release.json', old)
            calls = []
            def play(command, values, **kw):
                calls.append(Path(command[3]).stem)
                self.assertEqual(json.loads((directory/'release.json').read_text()), old)
                if calls[-1] == 'uncloud_apps_release' and fail[0]:
                    raise RuntimeError('verification failed')
            fail = [True]
            with patch.object(module, 'inventory_directory', return_value=directory), patch.object(
                    module, 'connect'), patch.object(module, 'provisioning_key', return_value=nullcontext('key')), patch.object(
                    module, 'prepare_trust', return_value=[]), patch.object(module, 'resolve_environment', return_value={}), patch.object(
                    module, 'prepare_ingress', return_value={}), patch.object(module, 'run_ansible', side_effect=play), patch.dict(
                    __import__('os').environ), patch.object(sys,'argv',['update','demo']):
                with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                    module.main()
                self.assertTrue((directory/'release.candidate.json').exists())
                fail[0] = False
                module.main()
                self.assertEqual(calls[-1], 'uncloud_ha_verify')
                self.assertEqual(json.loads((directory/'release.json').read_text()), manifest)
                self.assertFalse((directory/'release.candidate.json').exists())

    def test_bare_metal_chat_requires_final_gate_and_skips_confirmed_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state/'installation.json').write_text(json.dumps({'company':'demo','config':{'front_url':'https://app.example.org'},
                'bare_metal_servers':{'demo-a':{'uncloud_expected_hostname':'example-a','ansible_host':'192.0.2.1'}}}))
            (state/'bare-metal-release.json').write_text('{"release":"prod_1.1.30"}')
            timing = state/'timings-setup.json'
            timing.write_text('{"playbooks":[]}')
            with self.assertRaises(ValueError):
                notifications.notify_bare_metal(state, 'demo')
            timing.write_text('{"playbooks":[{"playbook":"uncloud_ha_verify.yml","status":"passed"}]}')
            with patch.object(notifications,'webhook',return_value='fixture'), patch.object(notifications,'post') as post:
                self.assertEqual(notifications.notify_bare_metal(state,'demo')['status'], 'sent')
                self.assertTrue(notifications.notify_bare_metal(state,'demo')['already_sent'])
                post.assert_called_once()
