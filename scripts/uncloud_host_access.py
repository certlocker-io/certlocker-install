"""Save the dedicated provisioning identity and verified server facts in Trust."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import re
import resource
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone

from uncloud_support import company_slug, MISSING, Trust, inventory_directory, write_private

OPERATOR_TRUST_URL = 'https://trust.certlocker.io/rest'


def provisioning_record(company):
    return 'ansible.uncloud.' + company_slug(company) + '.hosts.provisioning.ssh_key'


def runtime_ssh_key(path):
    """Resolve a saved logical identity to the current run's memory-backed file."""
    source = os.environ.get('CERTLOCKER_SSH_KEY_SOURCE')
    temporary = os.environ.get('CERTLOCKER_SSH_KEY_PATH')
    path = Path(path).expanduser().absolute()
    if source and temporary and path == Path(source).expanduser().absolute():
        return Path(temporary)
    return path


def public_key(private):
    from cryptography.hazmat.primitives import serialization
    raw = private.encode()
    loader = serialization.load_ssh_private_key if raw.startswith(b'-----BEGIN OPENSSH') else serialization.load_pem_private_key
    key = loader(raw, password=None)
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    if not public.startswith('ssh-ed25519 '):
        raise ValueError('This environment requires a dedicated Ed25519 SSH identity')
    return public


def generate_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()


@contextmanager
def memory_key(key):
    memory = Path('/dev/shm')
    filesystem = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(memory)],
                                capture_output=True, text=True, check=True).stdout.strip()
    if filesystem != 'tmpfs':
        raise ValueError('Provisioning SSH access requires memory-backed temporary storage')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix='certlocker-ssh-', dir=memory) as temporary:
        handlers = {}

        def interrupted(signum, frame):
            raise SystemExit(128 + signum)

        try:
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGTERM, signal.SIGHUP):
                    previous = signal.getsignal(signum)
                    if previous == signal.SIG_DFL:
                        signal.signal(signum, interrupted)
                        handlers[signum] = previous
            path = Path(temporary) / 'identity'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(key)
            yield str(path)
        finally:
            for signum, previous in handlers.items():
                signal.signal(signum, previous)


@contextmanager
def key_mapping(source, temporary):
    names = ('CERTLOCKER_SSH_KEY_SOURCE', 'CERTLOCKER_SSH_KEY_PATH')
    previous = {name: os.environ.get(name) for name in names}
    os.environ[names[0]] = str(Path(source).expanduser().absolute())
    os.environ[names[1]] = str(temporary)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextmanager
def setup_key(company, config, state, *, allow_create=False):
    """Enroll before provisioning; retain only public references between runs."""
    company = company_slug(company)
    source = Path(config['ssh_private_key']).expanduser().absolute()
    user = config.get('ssh_user', 'ucdeploy')
    name = provisioning_record(company)
    snapshot = Path(state) / 'provisioning-key.json'
    saved = json.loads(snapshot.read_text()) if snapshot.exists() else None
    if saved is not None and (not isinstance(saved, dict) or saved.get('schema_version') != 1
                  or saved.get('company') != company or saved.get('ssh_user') != user
                  or saved.get('key_record') != name or saved.get('source') != str(source)):
        raise ValueError('Saved provisioning identity belongs to another installation')
    trust = Trust(api_url=OPERATOR_TRUST_URL, group=config.get('trust_group', company), account_id=config.get('trust_account_id'))
    if config.get('registry_mode') == 'gcp':
        trust.bind_account(company, config.get('trust_account_id'), config.get('trust_account_marker_id'))
    key = trust.get(name)
    local = runtime_ssh_key(source)
    local_key = read_key(local)[0] if local.exists() or local.is_symlink() else None
    if key is MISSING:
        if local_key is not None:
            candidate = local_key
        elif saved is None:
            # Migrate an installation whose original key is already enrolled.
            directory = inventory_directory(company)
            references = directory / 'host-access.json'
            if references.exists():
                hosts = json.loads((directory / 'hosts.json').read_text())['all']['children']['uncloud']['hosts']
                _, candidate = load_host_access(company, json.loads(references.read_text()), hosts, trust, user=user)
            elif allow_create:
                candidate = generate_key()
            else:
                raise ValueError('Original provisioning key is unavailable in Trust; resume will not generate a replacement')
        else:
            raise ValueError('Original provisioning key is unavailable in Trust; resume will not generate a replacement')
        key = trust.ensure_named(name, company, lambda: candidate, secret_type='PEM', username=user)
        if key != candidate:
            raise ValueError('Trust provisioning key differs; refusing replacement')
    if not isinstance(key, str):
        raise ValueError('Trust provisioning SSH key is unavailable')
    _, fingerprint = key_identity(key.encode())
    public = public_key(key)
    if local_key is not None and local_key != key:
        raise ValueError('Local provisioning key differs from Trust; refusing replacement')
    if saved is not None and (saved.get('fingerprint') != fingerprint or saved.get('ssh_public_key') != public):
        raise ValueError('Trust provisioning key differs from the saved installation')
    if trust.get(name) != key:
        raise ValueError('Trust provisioning key read-back failed; no infrastructure was changed')
    document = dict(schema_version=1, company=company, ssh_user=user, source=str(source),
                    key_record=name, fingerprint=fingerprint, ssh_public_key=public)
    write_private(snapshot, json.dumps(document, indent=2) + '\n')
    # Old installers wrote a persistent dedicated key. Remove it only after its
    # identical remote copy and the non-secret recovery reference are verified.
    if source.exists() or source.is_symlink():
        if read_key(source)[0] != key:
            raise ValueError('Local provisioning key changed; refusing removal')
        source.unlink()
        public_path = Path(str(source) + '.pub')
        if (public_path.is_file() and not public_path.is_symlink()
                and public_path.read_text().split()[:2] == public.split()):
            public_path.unlink()
    with memory_key(key) as temporary, key_mapping(source, temporary):
        yield public


def destroy_public_key(config, state, terraform):
    """Teardown needs only public Terraform input, never a retained private key."""
    snapshot = Path(state) / 'provisioning-key.json'
    if snapshot.exists():
        return json.loads(snapshot.read_text())['ssh_public_key']
    path = Path(config['ssh_private_key']).expanduser()
    public_path = Path(str(path) + '.pub')
    if public_path.is_file():
        return public_path.read_text().strip()
    state_file = Path(terraform) / 'terraform.tfstate'
    if state_file.exists():
        for row in json.loads(state_file.read_text()).get('resources', []):
            if row.get('type') == 'google_compute_instance':
                for instance in row.get('instances', []):
                    metadata = instance.get('attributes', {}).get('metadata', {}) or {}
                    for entry in metadata.get('ssh-keys', '').splitlines():
                        if entry.startswith(config.get('ssh_user', 'ucdeploy') + ':ssh-ed25519 '):
                            return entry.split(':', 1)[1]
    # Empty/partial Terraform states still validate their required variables.
    # This public-only value is never applied to a server in a destroy plan.
    return public_key(generate_key())


@contextmanager
def installation_key(company, directory, marker):
    """Support standalone maintenance as well as children of an active setup."""
    source = marker['ssh_key_path']
    active = runtime_ssh_key(source)
    if active != Path(source).expanduser().absolute():
        read_key(active)
        yield str(active)
        return
    inventory = json.loads((Path(directory) / 'hosts.json').read_text())['all']['children']['uncloud']
    values = inventory.get('vars', {})
    trust = Trust(api_url=OPERATOR_TRUST_URL, group=values.get('uncloud_trust_group', company), account_id=values.get('uncloud_trust_account_id'))
    if values.get('uncloud_registry_mode') == 'gcp':
        trust.bind_account(company, values.get('uncloud_trust_account_id'), values.get('uncloud_trust_account_marker_id'))
    with provisioning_key(company, directory, inventory['hosts'], trust, marker['ssh_user']) as temporary:
        with key_mapping(source, temporary):
            yield temporary


def read_key(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or not 0 < info.st_size < 32768):
            raise ValueError('Provisioning SSH key must be an owner-only regular file')
        raw = stream.read(32768)
    return key_identity(raw)


def key_identity(raw):
    from cryptography.hazmat.primitives import serialization
    try:
        loader = serialization.load_ssh_private_key if raw.startswith(b'-----BEGIN OPENSSH') else serialization.load_pem_private_key
        key = loader(raw, password=None)
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(public.split()[1])).digest()).decode().rstrip('=')
        return raw.decode(), fingerprint
    except (ValueError, TypeError, UnicodeError):
        raise ValueError('Dedicated provisioning key must be a supported unencrypted SSH private key') from None


def save_host_access(company, trust, key_path, user, hosts, ssh, config):
    company = company_slug(company)
    facts = {}
    script = ("import json,platform,socket,pathlib; o=platform.freedesktop_os_release(); "
              "print(json.dumps(dict(hostname=socket.gethostname().split('.')[0],"
              "os=o.get('ID'),os_version=o.get('VERSION_ID'),architecture=platform.machine(),"
              "machine_id=pathlib.Path('/etc/machine-id').read_text().strip())))")
    for name, host in sorted(hosts.items()):
        value = json.loads(ssh(key_path, host['ansible_host'], shlex.join(['python3', '-c', script]), user=user))
        if value.get('hostname') != host['uncloud_expected_hostname'] or value.get('os') != 'ubuntu':
            raise ValueError('Server identity or Ubuntu platform differs from the enrolled host')
        if not value.get('machine_id') or not value.get('os_version') or not value.get('architecture'):
            raise ValueError('Server platform details are incomplete')
        facts[name] = dict(value, public_ip=host['ansible_host'], mesh_ip=host.get('uncloud_mesh_ip'),
                           provider=host['uncloud_provider'], ssh_user=user, ssh_port=22)
        hosting = config.get('hosting', {})
        if hosting.get('provider') == 'google':
            facts[name].update(provider='google', enrollment_method=host['uncloud_provider'],
                               project=hosting.get('project'), zone=hosting.get('zones', {}).get(name))
        elif host['uncloud_provider'] == 'google':
            facts[name].update(project=config.get('google_project'), zone=config['nodes'][name].get('zone'))
    private, fingerprint = read_key(Path(key_path))
    binding = {'company': company, 'user': user, 'fingerprint': fingerprint,
               'machines': {name: {'machine_id': fact['machine_id'], 'public_ip': fact['public_ip']} for name, fact in facts.items()}}
    installation = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()[:20]
    prefix = 'ansible.uncloud.' + company + '.hosts.' + installation
    key_name = prefix + '.ssh_key'
    saved = trust.ensure_named(key_name, company, lambda private=private: private, secret_type='PEM', username=user)
    if saved != private:
        raise ValueError('Trust provisioning key differs from this installation; refusing replacement')
    del private, saved
    document = {'schema_version': 1, 'company': company, 'installation_id': installation,
                'ssh_key_record': key_name, 'ssh_key_fingerprint': fingerprint, 'hosts': facts}
    snapshot = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()[:12]
    inventory_name = prefix + '.inventory.' + snapshot
    stored = trust.ensure_named(inventory_name, company, lambda: document)
    if stored != document:
        raise ValueError('Trust host inventory read-back differs from the verified platform')
    print('Provisioning SSH key and verified host platforms saved in company Trust.', flush=True)
    return {'installation_id': installation, 'ssh_key_record': key_name, 'host_inventory_record': inventory_name}


def load_host_access(company, references, hosts, trust, user=None):
    """Read the original key from operator Trust and bind it to this installed pair."""
    company = company_slug(company)
    installation = references.get('installation_id', '')
    if not re.fullmatch(r'[a-f0-9]{20}', installation):
        raise ValueError('Invalid provisioning installation identity')
    prefix = 'ansible.uncloud.' + company + '.hosts.' + installation
    key_name = prefix + '.ssh_key'
    inventory_name = references.get('host_inventory_record', '')
    if references.get('ssh_key_record') != key_name or not re.fullmatch(re.escape(prefix) + r'\.inventory\.[a-f0-9]{12}', inventory_name):
        raise ValueError('Provisioning references must belong to this company installation')
    document = trust.get(inventory_name)
    if not isinstance(document, dict) or document.get('company') != company or document.get('installation_id') != installation:
        raise ValueError('Stored provisioning inventory belongs to a different installation')
    facts = document.get('hosts', {})
    if set(facts) != set(hosts) or len(facts) != 2:
        raise ValueError('Provisioning inventory must identify both installed servers')
    for name, host in hosts.items():
        if facts[name].get('public_ip') != host['ansible_host'] or facts[name].get('mesh_ip') != host['uncloud_mesh_ip']:
            raise ValueError('Stored provisioning addresses differ from the installed pair')
    users = {fact.get('ssh_user') for fact in facts.values()}
    if len(users) != 1 or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', next(iter(users)) or ''):
        raise ValueError('One verified provisioning SSH user is required')
    if user is not None and users != {user}:
        raise ValueError('Stored provisioning SSH user differs from the installation')
    key = trust.get(key_name)
    if not isinstance(key, str) or not key.startswith('-----BEGIN '):
        raise ValueError('Stored provisioning SSH key is unavailable')
    _, fingerprint = key_identity(key.encode())
    if document.get('ssh_key_record') != key_name or document.get('ssh_key_fingerprint') != fingerprint:
        raise ValueError('Stored provisioning SSH key differs from the verified installation')
    return document, key


@contextmanager
def provisioning_key(company, directory, hosts, trust, user):
    """Use the operator Trust key for updates without retaining a disk copy."""
    references = json.loads((Path(directory) / 'host-access.json').read_text())
    _, key = load_host_access(company, references, hosts, trust, user=user)
    with memory_key(key) as temporary:
        yield temporary


def platform_seed(company, group, account_id, owner_id, references, hosts, trust):
    """Import the same operator Trust SSH identity into the freshly installed Trust."""
    document, key = load_host_access(company, references, hosts, trust)
    company = company_slug(company)
    facts = document['hosts']
    installation = references['installation_id']
    users = {fact['ssh_user'] for fact in facts.values()}
    stamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')
    def asset(kind, name):
        return {'id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'certlocker:uncloud:' + company + ':' + installation + ':' + kind)),
                'account_id': account_id, 'created_by': owner_id, 'updated_by': owner_id,
                'groups': [group], 'name': name, 'status': 'ACTIVE',
                'date_created': stamp, 'date_updated': stamp}
    secret = dict(asset('provisioning-key', company + ' provisioning SSH key'), secret_type='PEM',
                  secret=json.dumps({'username': next(iter(users)), 'key': key}), version=0)
    platform = dict(asset('platforms', company + ' installed server platforms'), secret_type='CONFIGURATION',
                    secret=json.dumps({'value': document}), version=0)
    targets = []
    for index, (name, fact) in enumerate(sorted(facts.items())):
        # Name must stay short: Bastion login is token@host (max 75 chars).
        targets.append(dict(
            asset('platform-' + name, company[:20] + '-terminal-' + str(index + 1)),
            ip_address=fact['mesh_ip'], port=22, operating_system='LINUX', secret_id=secret['id'],
            description=(
                'Browser Terminal / interactive SSH (PTY). '
                'Ubuntu ' + fact['os_version'] + ' / ' + fact['architecture'] +
                ' / ' + fact['hostname'] + ' / public ' + fact['public_ip']
            ),
        ))
    # Interactive Terminal token for the provisioning account (no OpenSSH "restrict").
    # Certificate automation uses a separate cl-cert-deploy key with restrict (no PTY).
    token_id = 'ssh-' + hashlib.sha256(
        (company + ':' + installation + ':terminal-ssh').encode()
    ).hexdigest()[:32]
    if any(len(token_id + '@' + target['name']) > 75 for target in targets):
        raise ValueError('Terminal SSH login exceeds the Bastion token limit')
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).replace(tzinfo=None)
    token = dict(
        asset('terminal-token', company + ' Terminal SSH'),
        id=token_id,
        token_type='HOST',
        protocols=['SSH', 'SFTP'],
        hosts=[host['id'] for host in targets],
        group_access=[group],
        secret_id=secret['id'],
        user_id=owner_id,
        single_use=False,
        auto_rotate=False,
        start_time=stamp,
        duration={'interval': 365, 'unit': 'DAYS'},
        expires=expires.isoformat(timespec='milliseconds'),
        description='Use with *-terminal-* hosts for browser Terminal / interactive SSH (PTY enabled)',
    )
    return {'secrets': [secret, platform], 'hosts': targets, 'tokens': [token]}
