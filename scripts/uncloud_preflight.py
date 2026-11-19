"""Read-only local controller checks before setup asks for servers or secrets."""
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def controller_swap_disabled():
    swaps=Path('/proc/swaps')
    if swaps.exists() and len(swaps.read_text().splitlines())<=1:
        return True
    limit=Path('/sys/fs/cgroup/memory.swap.max')
    return limit.exists() and limit.read_text().strip()=='0'


def check_controller(require_google=False, require_no_swap=False, require_terraform=False):
    problems = []
    if sys.version_info < (3, 10):
        problems.append('Python 3.10 or newer')
    if platform.system() != 'Linux':
        problems.append('a Linux deployment runtime (on macOS use the top-level launcher and its packaged controller)')
    # Customer workstations run these tools directly — do not require operator-only wrappers.
    commands = [
        'ssh', 'ssh-keygen', 'openssl', 'ansible-playbook', 'ansible-galaxy',
        'uc',
    ]
    if require_google:
        commands.append('gcloud')
    if require_terraform:
        commands.append('terraform')
    for name in commands:
        if not shutil.which(name):
            problems.append(name)
    for module, package in (('yaml', 'PyYAML'), ('cryptography', 'cryptography'), ('argon2', 'argon2-cffi')):
        if importlib.util.find_spec(module) is None:
            problems.append('Python package ' + package)
    if require_no_swap and platform.system() == 'Linux' and not controller_swap_disabled():
        problems.append('swap disabled on the dedicated customer deployment controller')
    if shutil.which('uc'):
        result = subprocess.run(['uc', 'version'], capture_output=True, text=True, timeout=15)
        if result.returncode or not re.search(r'Version:\s+0\.21\.0(?:\s|$)', result.stdout):
            problems.append('mesh CLI (uc) 0.21.0')
    if require_terraform and shutil.which('terraform'):
        result = subprocess.run(['terraform', 'version', '-json'], capture_output=True, text=True, timeout=15)
        try:
            version = json.loads(result.stdout).get('terraform_version', '') if result.returncode == 0 else ''
        except ValueError:
            version = ''
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version or ''):
            problems.append('terraform (working terraform version)')
    if shutil.which('ansible-galaxy'):
        result = subprocess.run(['ansible-galaxy', 'collection', 'list', '--format', 'json'],
                                capture_output=True, text=True, timeout=30)
        try:
            collections = json.loads(result.stdout) if result.returncode == 0 else {}
        except ValueError:
            collections = {}
        for name, version in (('ansible.posix', '1.5.4'), ('community.general', '8.3.0')):
            actual = next((items[name].get('version') for items in collections.values() if name in items), None)
            if actual != version:
                problems.append('Ansible collection ' + name + ':' + version)
    if problems:
        raise ValueError('Controller prerequisites missing or incompatible: ' + '; '.join(problems))
    print(
        'Controller tools checked: Python, OpenSSH, OpenSSL, '
        'PyYAML, cryptography, Argon2, Ansible collections and mesh CLI (uc) 0.21.0.',
        flush=True,
    )
    return {'controller_tools': 'passed', 'platform': platform.system()}
