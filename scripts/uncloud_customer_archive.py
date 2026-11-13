"""Archive installation JSON in the customer's installed Trust using its existing loader."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from uncloud_host_access import runtime_ssh_key
from uncloud_ssh import SSH_OPTIONS
from uncloud_support import inventory_directory, run_ansible, trust_name

ROOT = Path(__file__).resolve().parents[1]


def database_query(key, address, user, known_hosts, query):
    inner = ('export PGPASSWORD="$(cat /run/lab-secrets/postgres)" PGSSLMODE=require; '
             'exec psql -h 127.0.0.1 -U postgres -d certlocker -Atq -v ON_ERROR_STOP=1')
    remote = shlex.join(['sudo', '-n', 'docker', 'exec', '-i', 'certlocker-uncloud-postgres',
                        'bash', '-ec', inner])
    try:
        result = subprocess.run(['ssh', *SSH_OPTIONS, '-o', 'StrictHostKeyChecking=yes',
                                 '-o', 'UserKnownHostsFile=' + str(known_hosts), '-i', str(key),
                                 user + '@' + address, remote], input=query,
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Database request failed')
        return json.loads(result.stdout.strip()) if result.stdout.strip() else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeError('Customer Trust archive query failed; private response suppressed') from None


def verify_customer_copy(row, expected, document, master_key):
    if not isinstance(row, dict) or any(row.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Customer Trust archive identity differs from the intended account and user')
    try:
        # Released SecretUtils format: OB:base64(12-byte IV):base64(ciphertext+tag).
        # Decrypt just this record in memory; never dump the customer's secret table.
        value = row['secret']
        if not isinstance(value, str) or not value.startswith('OB:'):
            raise ValueError('Archive must be encrypted at rest')
        iv, encrypted = value[3:].split(':', 1)
        plain = AESGCM(master_key).decrypt(base64.b64decode(iv, validate=True),
                                         base64.b64decode(encrypted, validate=True), None)
        if json.loads(plain) != {'value': document}:
            raise ValueError('Archive content differs')
    except (ValueError, KeyError, TypeError, InvalidTag):
        raise RuntimeError('Customer Trust installer JSON read-back did not match; private response suppressed') from None


def archive_customer_installation(company, config, cycle, document, digest, operator_trust):
    directory = inventory_directory(company)
    marker = json.loads((directory / '.setup.json').read_text())
    if (marker.get('company') != company
            or Path(marker['state_dir']).resolve() != Path(cycle['state_dir']).resolve()
            or sorted(marker['addresses']) != sorted(node['public_ip'] for node in cycle['nodes'].values())):
        raise ValueError('Customer archive target differs from the verified installation')
    inventory = json.loads((directory / 'hosts.json').read_text())['all']['children']['uncloud']
    hosts = inventory['hosts']
    if (set(hosts) != set(cycle['nodes']) or inventory['vars']['ansible_user'] != marker['ssh_user']
            or any(hosts[name]['ansible_host'] != node['public_ip'] for name, node in cycle['nodes'].items())):
        raise ValueError('Customer archive inventory differs from the verified servers')
    email = config.get('initial_admin_email')
    if not email or operator_trust.get(trust_name(company, 'vault_certlocker_initial_admin_email')) != email:
        raise ValueError('Customer archive owner differs from the enrolled company administrator')
    if operator_trust.get(trust_name(company, 'vault_certlocker_company_account_domain')) != config.get('account_domain'):
        raise ValueError('Customer archive account domain differs from enrollment')
    try:
        master_key = base64.b64decode(operator_trust.get(trust_name(company, 'vault_certlocker_master_key')), validate=True)
        if len(master_key) != 32:
            raise ValueError('Invalid key length')
    except (ValueError, TypeError):
        raise ValueError('Company master key is unavailable for customer archive verification') from None
    key = runtime_ssh_key(marker['ssh_key_path'])
    user = marker['ssh_user']
    primary = hosts[next(iter(hosts))]['ansible_host']
    known_hosts = Path(cycle['state_dir']) / 'known_hosts'

    def query(sql):
        return database_query(key, primary, user, known_hosts, sql)

    # Find the already-created superuser. This step creates no account, login or token.
    escaped_email = email.replace("'", "''")
    owners = query("SELECT json_agg(json_build_object('account_id',a.id,'user_id',u.id)) "
                   "FROM jeremy.users u JOIN jeremy.accounts a ON a.id=u.accountid "
                   "WHERE lower(u.email)=lower('" + escaped_email + "') AND u.nodetype='EDGE' "
                   "AND u.status='ACTIVE' AND a.status='ACTIVE' AND 'SUPER_USER_FE'=ANY(u.roleids);")
    if (not isinstance(owners, list) or len(owners) != 1 or not isinstance(owners[0], dict)
            or not owners[0].get('account_id') or not owners[0].get('user_id')):
        raise ValueError('Customer Trust must have exactly one active installed company superuser')
    owner = owners[0]
    identifier = str(uuid.uuid5(uuid.NAMESPACE_URL,
        'certlocker:installation-json:' + company + ':' + str(owner['account_id']) + ':' + digest))
    name = company + ' installer JSON ' + digest[:12]
    expected = {'id': identifier, 'account_id': owner['account_id'], 'user_id': owner['user_id'],
                'name': name, 'secret_type': 'CONFIGURATION'}
    readback = ("SELECT json_agg(json_build_object('id',id,'account_id',accountid,'user_id',userid,"
                "'name',name,'secret_type',secrettype,'secret',secret)) "
                "FROM jeremy.private_secrets WHERE id='" + identifier + "';")
    rows = query(readback)
    if not rows:
        stamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='seconds')
        row = dict(expected, created_by=owner['user_id'], create_by_email=email, version=1,
                   date_created=stamp, date_updated=stamp,
                   description='Verified installation JSON and server inventory, also archived at trust.certlocker.io.',
                   secret=json.dumps({'value': document}, sort_keys=True))
        # Existing loader encrypts the field with the installed master key and
        # carries the payload only through stdin/tmpfs, with Ansible no_log.
        try:
            run_ansible(['ansible-playbook', '-i', directory / 'hosts.json',
                         ROOT / 'playbooks/uncloud_certificate_seed.yml', '--private-key', str(key),
                         '-e', json.dumps({'ansible_remote_tmp': '/run/certlocker-' + company + '-ansible',
                                          'ansible_ssh_common_args': shlex.join([
                                              *SSH_OPTIONS, '-o', 'StrictHostKeyChecking=yes',
                                              '-o', 'UserKnownHostsFile=' + str(known_hosts)])})],
                        {'uncloud_certificate_seed': {'private_secrets': [row]}})
        except subprocess.CalledProcessError:
            raise RuntimeError('Customer Trust archive loader did not complete; resume to verify or retry the copy') from None
        rows = query(readback)
    if not isinstance(rows, list) or len(rows) != 1:
        raise RuntimeError('Customer Trust installer JSON could not be read back unambiguously')
    verify_customer_copy(rows[0], expected, document, master_key)
    return {'status': 'saved', 'record_id': identifier, 'record_name': name,
            'account_id': owner['account_id'], 'url': config.get('front_url', '')}
