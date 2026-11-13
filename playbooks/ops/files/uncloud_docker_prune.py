#!/usr/bin/env python3
"""Prune unused Docker objects while preserving running and current-release images."""
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import time

STATE_DIR = Path('/var/lib/certlocker-uncloud/docker-prune')
LOCK_FILE = STATE_DIR / 'cleanup.lock'


def docker(*args, allow_failure=False):
    result = subprocess.run(['/usr/bin/docker', *args], capture_output=True, text=True, timeout=600)
    if result.returncode and not allow_failure:
        raise RuntimeError(f'Docker cleanup operation failed: {args[0]}')
    return result


def current_release_refs():
    references = set()
    manifests = []
    for company_dir in Path('/opt/certlocker').glob('*/uncloud-apps'):
        manifests += [company_dir / 'release.json', company_dir / 'release.rollback.json']
    for manifest_path in manifests:
        if not manifest_path.is_file():
            continue
        try:
            document = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError):
            raise RuntimeError('Could not read a current/rollback release manifest; refusing image cleanup') from None
        services = document.get('services')
        if not isinstance(services, dict):
            raise RuntimeError('Unexpected release manifest; refusing image cleanup')
        for service in services.values():
            image = service.get('image') if isinstance(service, dict) else None
            if not isinstance(image, str) or not image:
                raise RuntimeError('Invalid image pin in company release manifest')
            references.add(image)
    for image_path in Path('/opt/certlocker').glob('*/uncloud-monitoring/images.json'):
        try:
            images = json.loads(image_path.read_text())
        except (OSError, json.JSONDecodeError):
            raise RuntimeError('Could not read current monitoring image pins; refusing image cleanup') from None
        if not isinstance(images, dict) or any(not isinstance(value, str) or not value for value in images.values()):
            raise RuntimeError('Invalid monitoring image pins; refusing image cleanup')
        references.update(images.values())
    return references


def prune_honeypot_logs():
    names = docker('volume', 'ls', '--quiet').stdout.split()
    selected = [name for name in names if name.endswith('_cowrie_log') or name == 'cowrie_log']
    removed = 0
    cutoff = time.time() - 14 * 24 * 60 * 60
    for name in selected:
        info = json.loads(docker('volume', 'inspect', name).stdout)[0]
        expected = Path('/var/lib/docker/volumes') / name / '_data'
        mountpoint = Path(info.get('Mountpoint', '')).resolve()
        if mountpoint != expected or not mountpoint.is_dir() or mountpoint.is_symlink():
            raise RuntimeError('Cowrie log volume path differs from the expected Docker volume; refusing cleanup')
        for entry in mountpoint.rglob('*'):
            try:
                details = entry.lstat()
                if stat.S_ISREG(details.st_mode) and details.st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except FileNotFoundError:
                continue
    print(f'Honeypot log cleanup complete: removed {removed} files older than 14 days.')
    return removed


def main():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE_DIR.chmod(0o700)
    with LOCK_FILE.open('a') as lock:
        os.chmod(LOCK_FILE, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prune_honeypot_logs()
        docker('container', 'prune', '--force')
        docker('builder', 'prune', '--all', '--force')

        image_ids = sorted(set(docker('image', 'ls', '--all', '--no-trunc', '--quiet').stdout.split()))
        if not image_ids:
            print('No Docker images found; no image cleanup needed.')
            return
        container_ids = docker('ps', '--all', '--no-trunc', '--quiet').stdout.split()
        containers = json.loads(docker('inspect', *container_ids).stdout if container_ids else '[]')
        used = {item.get('Image') for item in containers if isinstance(item, dict)}
        deployed_refs = current_release_refs()
        if not deployed_refs:
            print('No current or rollback release manifest found; keeping all Docker images.')
            return
        images = json.loads(docker('image', 'inspect', *image_ids).stdout)
        removed = 0
        kept = 0
        for image in images:
            image_id = image.get('Id')
            if not isinstance(image_id, str) or not image_id:
                raise RuntimeError('Docker returned an invalid image identity; refusing image cleanup')
            references = set(image.get('RepoDigests') or []) | set(image.get('RepoTags') or [])
            if image_id in used or references & deployed_refs:
                kept += 1
                continue
            # Docker refuses rmi IMAGE_ID when an unused image has multiple tags.
            # Remove its tags together, without --force, so container-use checks
            # still protect images acquired by a concurrent deployment.
            tags = sorted(tag for tag in (image.get('RepoTags') or []) if tag != '<none>:<none>')
            result = docker('image', 'rm', *(tags or [image_id]), allow_failure=True)
            if result.returncode:
                kept += 1
            else:
                removed += 1
        print(f'Docker cleanup complete: removed {removed} unused images, retained {kept}; '
              'database volumes were not pruned.')


if __name__ == '__main__':
    main()
