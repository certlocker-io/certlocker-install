"""Observe each installed node's public IP and archive successful setup JSON in Trust."""
import hashlib
import ipaddress
import json
import os
import tempfile
import uuid
from pathlib import Path

from uncloud_host_access import runtime_ssh_key
from certlocker_gateway import operator_gateway
from uncloud_customer_archive import archive_customer_installation
from uncloud_ssh import run_ssh
from uncloud_support import Trust, company_slug, write_private

PUBLIC_IP_COMMAND = ("curl --ipv4 --noproxy '*' --fail --silent --show-error "
                     "--connect-timeout 10 --max-time 20 --retry 2 --retry-delay 2 https://ifconfig.me/ip")


def require_verified(cycle):
    if (cycle.get('status') != 'passed' or cycle.get('verified_through') != 'apps'
            or not cycle.get('install_passed') or not cycle.get('verify_passed')
            or not cycle.get('public_database_closed')):
        raise ValueError('Only a fully verified installation can be archived in Trust')


def collect_public_ips(config, cycle):
    require_verified(cycle)
    key = runtime_ssh_key(config['ssh_private_key'])
    known_hosts = Path(cycle['state_dir']) / 'known_hosts'
    observed = {}
    for name, node in sorted(cycle['nodes'].items()):
        try:
            # Execute on each node, never on the controller or against cloud metadata.
            output = run_ssh(key, node['public_ip'], PUBLIC_IP_COMMAND,
                             user=config.get('ssh_user', 'ucdeploy'), known_hosts=known_hosts,
                             wait_seconds=90, command_timeout=80).strip()
            address = ipaddress.IPv4Address(output)
            if not address.is_global:
                raise ValueError('Non-public IP')
        except (ValueError, RuntimeError, OSError):
            raise RuntimeError(f'{name}: installation checks passed, but the node public IP could not be '
                               'verified with curl https://ifconfig.me/ip. Check node HTTPS egress and resume; '
                               'no installation success notification was sent') from None
        observed[name] = str(address)
    for name, address in observed.items():
        cycle['nodes'][name]['reported_public_ip'] = address
        cycle['nodes'][name]['public_ip_source'] = 'https://ifconfig.me/ip (queried on node)'
    return observed


def report_verified_installation(company, release, state_dir, trust, provider):
    """Publish one non-secret completion report per installation, including retries."""
    company = company_slug(company)
    state_dir = Path(state_dir)
    path = state_dir / 'installation-report.json'
    if not path.exists():
        document = {'company': company, 'provider': provider, 'release': release,
                    'installation_id': uuid.uuid4().hex, 'status': 'installed_and_verified'}
        with tempfile.NamedTemporaryFile(mode='w', dir=state_dir) as tmp:
            json.dump(document, tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
            try:
                os.link(tmp.name, path)
            except FileExistsError:
                pass
    document = json.loads(path.read_text())
    if document['company'] != company or document['provider'] != provider:
        raise ValueError('Saved installation report belongs to a different deployment')
    name = f"ansible.uncloud.{company}.reports.{document['installation_id']}.installed"
    if trust.ensure_named(name, company, lambda: document) != document:
        raise RuntimeError('Issuing Trust did not confirm the installation report')
    print('Verified installation recorded in issuing Trust: ' + name, flush=True)


def archive_installation(company, config, cycle, company_config_path, install_config_path):
    require_verified(cycle)
    company = company_slug(company)
    for node in cycle['nodes'].values():
        if not ipaddress.IPv4Address(node['reported_public_ip']).is_global:
            raise ValueError('A verified public IP is required for every installed node')
    files = {}
    for name, path in (('company.json', company_config_path), ('install.json', install_config_path)):
        content = Path(path).read_text()
        if not isinstance(json.loads(content), dict):
            raise ValueError('Installer configuration must be a JSON object')
        files[name] = content
    document = {'schema_version': 1, 'company': company, 'generation': cycle['generation'],
                'status': 'installed_and_verified', 'release': cycle['final_release']['release'],
                'nodes': cycle['nodes'], 'files': files}
    digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
    name = f'ansible.uncloud.{company}.installations.{cycle["generation"]}.{digest}.installer_json'
    trust = Trust(api_url=operator_gateway(), group=config.get('trust_group'),
                  account_id=config.get('trust_account_id'))
    report_verified_installation(company, document['release'], cycle['state_dir'], trust, 'google')
    # Content-addressed snapshots preserve older successful installs and make resume
    # idempotent. No revoke/recreate or replacement of a different JSON snapshot.
    saved = trust.ensure_named(name, company, lambda: document)
    if saved != document or trust.get(name) != document:
        raise RuntimeError('Installation JSON read-back from Trust did not match; resume to complete the archive')
    receipt = {'status': 'operator_saved', 'installation_record': name, 'sha256': digest,
               'operator': {'status': 'saved', 'api_url': operator_gateway(),
                            'installation_record': name}, 'customer': {'status': 'pending'}}

    def save_receipt():
        serialized = json.dumps(receipt) + '\n'
        # Keep the operator reference even if the customer's copy needs a resume.
        write_private(Path(cycle['state_dir']) / ('installation-trust-' + digest + '.json'), serialized)
        write_private(Path(cycle['state_dir']) / 'installation-trust.json', serialized)

    save_receipt()
    receipt['customer'] = archive_customer_installation(company, config, cycle, document, digest, trust)
    if receipt['customer'].get('status') != 'saved':
        raise RuntimeError('Customer Trust installer JSON copy was not confirmed')
    receipt['status'] = 'saved'
    save_receipt()
    print('Installer JSON verified in both operator Trust and the installed customer Trust: ' + name, flush=True)
    return receipt
