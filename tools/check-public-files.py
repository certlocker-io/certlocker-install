#!/usr/bin/env python3
"""Check the explicit public source list without printing possible secret values."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOCAL_DIRS = {'.git', 'local', 'inventory', '__pycache__', '.pytest_cache'}
SECRET_PATTERNS = (
    rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----',
    rb'gh[pousr]_[A-Za-z0-9]{30,}',
    rb'github_pat_[A-Za-z0-9_]{40,}',
    rb'AKIA[0-9A-Z]{16}',
    rb'AIza[0-9A-Za-z_-]{35}',
    rb'"type"\s*:\s*"service_account"',
    rb'https://chat\.googleapis\.com/[^\s\x22\x27]+[?&]key=[^\s\x22\x27]+',
    rb'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
)
PRIVATE_PATTERNS = (
    rb'/home/(?!controller(?:/|[\x22\x27]))[a-z][a-z0-9_-]+/',
    rb'ansible\.(?:dev[0-9]+|[a-z0-9.-]+)\.certlocker_stack\.',
)



def audit(root, allowed):
    errors = []
    for relative in allowed:
        path = root / relative
        if Path(relative).is_absolute() or '..' in Path(relative).parts:
            errors.append('Unsafe allowlist path')
            continue
        if path.is_symlink() or not path.is_file():
            errors.append('Missing or nonregular public file: ' + relative)
            continue
        raw = path.read_bytes()
        if any(re.search(pattern, raw) for pattern in SECRET_PATTERNS):
            errors.append('Possible credential in: ' + relative)
        # This approved record locator is public metadata, never a credential.
        metadata_scan = raw
        if relative == 'scripts/uncloud_support.py':
            locator = b'ansible.' + b'dev04.certlocker_stack.' + b'vault_cr_pat'
            metadata_scan = metadata_scan.replace(locator, b'')
        if relative == 'scripts/uncloud_install_notification.py':
            # Approved operator notification record locator; never the webhook value.
            metadata_scan = metadata_scan.replace(
                b'ansible.' + b'certlocker.io.certlocker_stack.' + b'vault_noc_google_chat_webhook_url', b'')
        if any(re.search(pattern, metadata_scan) for pattern in PRIVATE_PATTERNS):
            errors.append('Internal configuration in: ' + relative)
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if relative.parts[:2] == ('uncloud', 'environments'):
            continue
        if any(part in LOCAL_DIRS for part in relative.parts):
            continue
        if (path.is_file() or path.is_symlink()) and str(relative) not in allowed:
            errors.append('Unexpected file outside public allowlist: ' + str(relative))
    return errors


def main():
    allowed = set(json.loads((ROOT / 'public-files.json').read_text()))
    errors = audit(ROOT, allowed)
    if (ROOT / '.git').exists():
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z'],
                                 check=True, capture_output=True).stdout.decode().split('\0')
        errors += ['Tracked file outside public allowlist: ' + name
                   for name in tracked if name and name not in allowed]
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'Public source check passed: {len(allowed)} allowlisted files; no configured credential patterns or internal markers found.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
