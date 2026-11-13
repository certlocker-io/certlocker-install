"""Send verified installation inventory to the operator Google Chat space."""
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from uncloud_support import NoRedirect, Trust, write_private

DEFAULT_SECRET_NAME = 'ansible.certlocker.io.certlocker_ha.vault_noc_google_chat_webhook_url'


def webhook(config):
    # This stays on the controller: never copy an operator webhook into a customer account.
    name = (config.get('install_chat_secret_name') or
            os.environ.get('CERTLOCKER_GOOGLE_CHAT_WEBHOOK_SECRET_NAME') or DEFAULT_SECRET_NAME)
    value = Trust(account_id=config.get('trust_account_id')).get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Installation Google Chat webhook is missing from the configured Trust record')
    value = value.strip()
    parsed = urllib.parse.urlsplit(value)
    query = urllib.parse.parse_qs(parsed.query)
    if (parsed.scheme != 'https' or parsed.netloc != 'chat.googleapis.com'
            or not re.fullmatch(r'/v1/spaces/[A-Za-z0-9_-]+/messages', parsed.path)
            or parsed.fragment or not query.get('key') or not query.get('token')):
        raise ValueError('Installation Google Chat webhook in Trust is invalid')
    return value


def preflight(config):
    try:
        webhook(config)
    except (ValueError, RuntimeError, OSError):
        print('Installation Google Chat webhook is unavailable or invalid. Configure install_chat_secret_name '
              'with the Trust record for the trust channel; installation can continue, but its notification is pending.', flush=True)
        return 'unavailable'
    return 'configured (delivery checked after installation)'


def installation_message(company, config, cycle, machine_names, machine_type, disk_size):
    lines = ['CertLocker installed — verification passed',
             'Company: ' + company, 'Deployment: ' + str(config.get('deployment', 'unknown')),
             'Google project: ' + str(config.get('google_project', 'unknown')),
             'Release: ' + str(cycle['final_release']['release']),
             'Installation: ' + cycle['generation']]
    for key, label in (('front_url', 'Front office'), ('backoffice_url', 'Backoffice'), ('grafana_url', 'Grafana')):
        if config.get(key):
            lines.append(label + ': ' + config[key])
    for name, node in sorted(cycle['nodes'].items()):
        size = config.get('nodes', {}).get(name, {}).get('machine_type', machine_type)
        lines.extend(['', 'Server: ' + machine_names.get(name, name),
                      'Public IP (ifconfig.me): ' + node['reported_public_ip'] + ' | Private IP: ' + node['private_ip'],
                      'Zone: ' + node['zone'] + ' | VM: ' + size + ' | Boot disk: ' + str(disk_size) + ' GiB',
                      'Instance ID: ' + str(node['instance_id']) + ' | State: ' + node['status']])
    lines.extend(['', 'Application, HTTPS routing and public database exposure checks passed.',
                  'Installer JSON saved at trust.certlocker.io: ' + cycle['installation_trust']['installation_record'],
                  'Customer Trust copy: ' + cycle['installation_trust']['customer']['record_name']])
    return '\n'.join(lines)


def post(url, message):
    # Incoming webhooks reject the Chat API's requestId parameter. Confirm the
    # response below and use the local receipt to skip confirmed deliveries.
    request = urllib.request.Request(url, method='POST',
        data=json.dumps({'text': message}).encode(), headers={'Content-Type': 'application/json; charset=utf-8'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError('Google Chat did not confirm delivery')
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Oversized response')
        result = json.loads(raw)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'Google Chat returned HTTP {error.code}; private response suppressed') from None
    except (OSError, ValueError):
        raise RuntimeError('Google Chat delivery could not be confirmed; private response suppressed') from None
    if (not isinstance(result, dict) or result.get('text') != message
            or not isinstance(result.get('name'), str) or not result['name'].startswith('spaces/')):
        raise RuntimeError('Google Chat did not confirm the exact installation message')


def notify_installation(company, config, cycle, machine_names, machine_type, disk_size):
    if (cycle.get('status') != 'passed' or cycle.get('verified_through') != 'apps'
            or not cycle.get('install_passed') or not cycle.get('verify_passed')
            or not cycle.get('public_database_closed')
            or cycle.get('installation_trust', {}).get('status') != 'saved'
            or cycle.get('installation_trust', {}).get('operator', {}).get('status') != 'saved'
            or cycle.get('installation_trust', {}).get('customer', {}).get('status') != 'saved'):
        return {'status': 'not_sent', 'reason': 'Full installation verification has not passed'}
    try:
        message = installation_message(company, config, cycle, machine_names, machine_type, disk_size)
        url = webhook(config)
        # Include destination in the private digest so changing the channel does not
        # inherit another channel's receipt. Neither URL nor response body is saved.
        digest = hashlib.sha256((url + '\n' + message).encode()).hexdigest()
        marker = Path(cycle['state_dir']) / 'install-chat.json'
        if marker.exists():
            previous = json.loads(marker.read_text())
            if previous.get('status') == 'sent' and previous.get('digest') == digest:
                return {'status': 'sent', 'already_sent': True}
        post(url, message)
        write_private(marker, json.dumps({'status': 'sent', 'digest': digest}) + '\n')
    except (ValueError, KeyError, TypeError, RuntimeError, OSError):
        print('Installation passed, but Google Chat delivery was not confirmed. Check the trust-channel '
              'webhook record and network access, then resume to retry the notification.', flush=True)
        return {'status': 'unconfirmed'}
    print('Installed server details delivered to Google Chat.', flush=True)
    return {'status': 'sent'}
