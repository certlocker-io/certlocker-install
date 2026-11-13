"""Bounded, private-key-only SSH for installation readiness and read-only probes."""
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SSH_OPTIONS = ['-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
               '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
               '-o', 'KbdInteractiveAuthentication=no', '-o', 'ConnectTimeout=10',
               '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=10',
               '-o', 'ServerAliveCountMax=2', '-o', 'ControlMaster=no', '-o', 'ControlPath=none']


def failure_reason(stderr):
    """Classify diagnostics without printing remote output, key paths or command text."""
    text = (stderr or '').lower()
    if 'remote host identification has changed' in text or 'host key verification failed' in text:
        return 'Host key verification failed; verify the server identity and installation known_hosts file', True
    if 'too many authentication failures' in text:
        return 'SSH rejected too many identities; check the dedicated provisioning identity and SSH configuration', True
    if (any(term in text for term in ('no such identity', 'invalid format', 'bad permissions', 'unprotected private key'))
            or 'identity file' in text and 'not accessible' in text):
        return 'The provisioning private key is missing or unreadable; reload the original key from Trust', True
    if 'permission denied' in text or 'authentication failed' in text:
        return 'The server rejected the provisioning key; check the SSH user, VM metadata key and Google guest agent/OS Login settings', False
    if 'connection refused' in text:
        return 'SSH is not listening yet; check VM startup and the SSH service', False
    if any(term in text for term in ('timed out', 'no route to host', 'network is unreachable')):
        return 'SSH is unreachable; check the VM IP, firewall source /32, network route and SSH service', False
    if 'sudo:' in text:
        return 'The provisioning user is not ready for passwordless sudo', False
    if 'bad configuration option' in text or 'unsupported option' in text:
        return 'The local OpenSSH configuration contains an unsupported option', True
    return 'SSH connection closed or transport failed; check VM startup and SSH configuration', False


def run_ssh(key, host, command, user='ucdeploy', *, known_hosts=None,
            wait_seconds=60, command_timeout=30, readiness=False):
    """Retry read-only probes, with a monotonic deadline and useful safe diagnostics."""
    options = [*SSH_OPTIONS]
    if known_hosts is not None:
        options += ['-o', 'UserKnownHostsFile=' + str(known_hosts), '-o', 'StrictHostKeyChecking=yes']
    else:
        options += ['-o', 'StrictHostKeyChecking=accept-new']
    args = ['ssh', *options, '-i', str(key), user + '@' + host, command]
    deadline = time.monotonic() + wait_seconds
    next_notice = 0
    reason = 'SSH did not become ready'
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f'{host}: {reason}. SSH readiness deadline ({wait_seconds}s) reached; retry the installation after correcting access')
        try:
            result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True,
                                    timeout=min(command_timeout, remaining), check=False)
        except subprocess.TimeoutExpired:
            reason, permanent = failure_reason('connection timed out')
        else:
            if result.returncode == 0:
                return result.stdout
            reason, permanent = failure_reason(result.stderr)
            if result.returncode != 255 and not readiness:
                raise RuntimeError(f'{host}: remote verification command failed (exit {result.returncode}); '
                                   + ('check passwordless sudo' if 'sudo:' in (result.stderr or '') else 'check the requested host service'))
            if permanent:
                raise RuntimeError(f'{host}: {reason}') from None
        now = time.monotonic()
        if now >= next_notice:
            print(f'Waiting for SSH provisioning on {host}: {reason} '
                  f'({max(0, int(deadline - now))}s remaining)', flush=True)
            next_notice = now + 30
        if now < deadline:
            time.sleep(min(5, deadline - now))


def wait_for_ssh(key, host, user='ucdeploy'):
    return run_ssh(key, host, 'sudo -n true', user=user, wait_seconds=600, readiness=True)
