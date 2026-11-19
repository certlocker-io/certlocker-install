"""Build company-scoped additive loader data for the released Trust application.

Returned documents contain private material and must only be transferred through
the existing in-memory deployment channel into tmpfs. Never print these objects.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
import urllib.error
import urllib.parse
import urllib.request


class CloudflareCredentialError(RuntimeError):
    """A token or its resource scope needs correction, rather than a network retry."""


def cloudflare_preflight(company, trust, zone, *, fallback_token=None):
    """Verify the user token and zone without exposing credentials or response bodies."""
    from uncloud_support import MISSING, NoRedirect, trust_name
    record = trust_name(company, 'vault_cloudflare_ini_key')
    token = trust.get(record)
    # Explicit teardown may be repeated after its first run revoked this record.
    # An operator-supplied replacement still undergoes all zone/token checks.
    if (token is MISSING or token == '') and fallback_token:
        token = fallback_token
    if isinstance(token, dict):
        token = token.get('api_token') or token.get('apiToken') or token.get('token')
    if isinstance(token, str) and token.strip().startswith('dns_cloudflare_api_token'):
        token = token.split('=', 1)[-1].strip()
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{10,256}', token.strip()):
        raise CloudflareCredentialError('Company Cloudflare API token is missing or malformed in Trust: ' + record)
    token = token.strip()
    permissions = (f'Use a User API Token with Zone DNS Edit and Zone Read on {zone}. '
                   'Cloudflare Load Balancing also needs Zone Load Balancers Edit and Account '
                   'Load Balancing: Monitors and Pools Edit on the zone owner account. '
                   'Check zone/account scope, expiry and IP restrictions. '
                   'Global API keys, Origin CA keys and account API tokens are not supported by the released Trust client.')

    def fail(data, path, status=None):
        # Only numeric codes are safe to echo: arbitrary API messages can reflect tokens.
        errors = data.get('errors', []) if isinstance(data, dict) else []
        codes = [item['code'] for item in errors if isinstance(item, dict)
                 and type(item.get('code')) is int] if isinstance(errors, list) else []
        details = ([f'HTTP {status}'] if status else []) + [f'code {code}' for code in codes[:5]]
        operation = 'user token verification' if path == 'user/tokens/verify' else 'DNS zone access'
        message = 'Cloudflare ' + operation + ' failed' + (' (' + ', '.join(details) + ')' if details else '')
        if status in (401, 403) or (status is None or status < 500 and status != 429) and any(
                code in (10000, 9103, 9106, 9107, 9109, 6003, 6111) for code in codes):
            raise CloudflareCredentialError(message + '. ' + permissions + ' Trust record: ' + record) from None
        if status == 429:
            message += '. Cloudflare rate limited the check; wait and retry with the same token'
        elif status is not None and status >= 500:
            message += '. Cloudflare is temporarily unavailable; retry with the same token'
        else:
            message += '. Check Cloudflare service status and retry; private response suppressed'
        raise RuntimeError(message) from None

    def request(path):
        req = urllib.request.Request('https://api.cloudflare.com/client/v4/' + path,
                                     headers={'Authorization': 'Bearer ' + token})
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
                data = json.load(response)
        except urllib.error.HTTPError as error:
            try:
                data = json.load(error)
            except (OSError, ValueError, TypeError):
                data = {}
            fail(data, path, error.code)
        except (OSError, ValueError):
            raise RuntimeError('Cloudflare DNS preflight could not reach or read the API; '
                               'check network access and retry with the same token') from None
        if not isinstance(data, dict) or data.get('success') is not True:
            fail(data, path)
        return data.get('result')

    zones = request('zones?name=' + urllib.parse.quote(zone, safe=''))
    if not isinstance(zones, list) or len(zones) != 1 or not isinstance(zones[0], dict) or zones[0].get('name') != zone:
        raise CloudflareCredentialError('Cloudflare token cannot identify DNS zone ' + zone + '. ' + permissions)
    zone_id = zones[0].get('id', '')
    if not isinstance(zone_id, str) or not re.fullmatch(r'[0-9a-f]{32}', zone_id) or zones[0].get('status') != 'active':
        raise ValueError('Cloudflare DNS zone is not active; activate the zone before continuing')
    if not isinstance(request('zones/' + zone_id + '/dns_records?per_page=1'), list):
        raise RuntimeError('Cloudflare returned an invalid DNS records response; retry with the same token')
    verification = request('user/tokens/verify')
    if not isinstance(verification, dict) or verification.get('status') != 'active':
        raise CloudflareCredentialError('Cloudflare user API token is not active. ' + permissions)
    return token, zone_id


def acme_profile_preflight(directory, profile='shortlived'):
    from uncloud_support import NoRedirect
    if directory != 'https://acme-v02.api.letsencrypt.org/directory' or profile != 'shortlived':
        raise ValueError('Lab issuance requires production Let\'s Encrypt and the shortlived profile')
    try:
        with urllib.request.build_opener(NoRedirect).open(directory, timeout=30) as response:
            data = json.load(response)
        profiles = data.get('meta', {}).get('profiles', {})
    except (OSError, ValueError, AttributeError):
        raise RuntimeError('Production ACME directory could not be verified') from None
    if profile not in profiles:
        raise ValueError('Production ACME directory does not advertise shortlived; refusing a longer-lived fallback')


def identity(company, trust):
    def generate():
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        def key():
            return rsa.generate_private_key(public_exponent=65537, key_size=3072)
        def pem(value):
            return value.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()).decode()
        ssh = key()
        return {'schema_version': 1, 'company': company, 'ssh_private_key': pem(ssh),
                'ssh_public_key': ssh.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                              serialization.PublicFormat.OpenSSH).decode(),
                'acme_key': pem(key()), 'domain_key': pem(key()),
                'host_token': 'ha-' + secrets.token_hex(16)}
    value = trust.ensure(company, 'vault_certlocker_certificate_identity', generate)
    if not isinstance(value, dict) or value.get('company') != company or value.get('schema_version') != 1:
        raise ValueError('Certificate deployment identity does not belong to this company')
    return value


def stable_id(company, kind):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'certlocker:uncloud:' + company + ':' + kind))


def automation_data(company, group, account_id, owner_id, hosts, material, now=None):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', company) or material['company'] != company:
        raise ValueError('Invalid company identity')
    if len(hosts) != 2 or len(set(hosts.values())) != 2:
        raise ValueError('Exactly two distinct HAProxy targets are required')
    for address in hosts.values():
        ipaddress.ip_address(address)
    now = now or datetime.now(timezone.utc)
    stamp = now.replace(tzinfo=None).isoformat(timespec='milliseconds')
    def asset(kind, name):
        return {'id': stable_id(company, kind), 'account_id': account_id,
                'created_by': owner_id, 'updated_by': owner_id, 'groups': [group],
                'name': name, 'status': 'ACTIVE', 'date_created': stamp, 'date_updated': stamp}
    secret = dict(asset('deployment-key', company + ' certificate deploy key'), secret_type='PEM',
                  secret=json.dumps({'username': 'cl-cert-deploy', 'key': material['ssh_private_key']}), version=0)
    # Name must stay short: Bastion login is token@host (max 75 chars).
    # These hosts are automation-only (cl-cert-deploy + OpenSSH restrict; no interactive PTY).
    targets = [dict(
        asset('host-' + name, company[:20] + '-cert-auto-' + str(index + 1)),
        ip_address=address, port=22, operating_system='LINUX', secret_id=secret['id'],
        description='Certificate automation only (no interactive Terminal / no PTY)',
    ) for index, (name, address) in enumerate(sorted(hosts.items()))]
    # Bastion validates the entire token@host login (maximum 75 characters).
    # Normalize the original lab identity deterministically without rotating its SSH key.
    host_token = material['host_token']
    if len(host_token) > 45 or '-' not in host_token:
        host_token = 'ha-' + hashlib.sha256(host_token.encode()).hexdigest()[:32]
    if any(len(host_token + '@' + target['name']) > 75 for target in targets):
        raise ValueError('Certificate automation login exceeds the Bastion token limit')
    token = dict(
        asset('deployment-token', company + ' HAProxy certificate automation'),
        id=host_token, token_type='HOST', protocols=['SSH', 'SFTP'],
        hosts=[host['id'] for host in targets], group_access=[group],
        secret_id=secret['id'], single_use=False, auto_rotate=False,
        # Must outlive many shortlived LE renewals (~160h each). Trust mints a
        # separate 1-hour CERTIFICATE access token per deploy; this HOST token is
        # what Bastion uses to SSH for every renewal until it expires.
        start_time=stamp, duration={'interval': 1825, 'unit': 'DAYS'},
        expires=(now + timedelta(days=1825)).replace(tzinfo=None).isoformat(timespec='milliseconds'),
        description='Automation only — use with *-cert-auto-* hosts; not for browser Terminal. Keep ACTIVE for HAProxy cert renewals.',
    )
    # Audit text must be a real helper stdout substring. The previous
    # "Certificate activated live" phrase existed only in this script template,
    # so console matching treated every failed run as activated.
    script = ('install certificate.combined to /run/certlocker-certificate-inbox/' + company + '/incoming.pem mode 0600\n'
              'exec sudo -n /usr/local/sbin/certlocker-certificate-activate --company ' + company + '\n'
              'audit true Certificate activated; both UI names verified\n')
    automation = dict(asset('certificate-automation', company + ' deploy UI certificate to both HAProxies'),
                      script_type='CERTIFICATE', token_id=token['id'],
                      hosts=[host['id'] for host in targets], script=script,
                      require_approval=False, stop_on_failure=True)
    return {'secrets': [secret], 'hosts': targets, 'tokens': [token], 'acme_automations': [automation]}


def issuance_data(company, group, account_id, owner_id, material, settings, cloudflare_token, cycle='initial', now=None):
    """Seed a real DNS-01 order; invoke only after provider preflight succeeds."""
    if settings.get('mode') != 'customer':
        raise ValueError('Our managed Cloudflare credential must not enter the customer loader')
    if not cloudflare_token or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', settings.get('email', '')):
        raise ValueError('ACME email and customer Cloudflare token are required')
    domains = settings.get('domains', [])
    if not domains or len(domains) > 10 or any(not re.fullmatch(r'(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name) for name in domains):
        raise ValueError('Explicit certificate domains are required')
    if settings.get('acme_directory') not in ('https://acme-v02.api.letsencrypt.org/directory',
                                              'https://acme-staging-v02.api.letsencrypt.org/directory'):
        raise ValueError('Use an explicitly supported public ACME directory')
    if settings.get('profile', 'shortlived') != 'shortlived':
        raise ValueError('The HA certificate contract requires the shortlived ACME profile')
    now = now or datetime.now(timezone.utc)
    stamp = now.replace(tzinfo=None).isoformat(timespec='milliseconds')
    asset = {'account_id': account_id, 'created_by': owner_id, 'updated_by': owner_id,
             'groups': [group], 'status': 'ACTIVE', 'date_created': stamp, 'date_updated': stamp}
    client = dict(asset, id=stable_id(company, 'acme-client'), name=company + ' UI ACME',
                  contacts=[settings['email']], key_pair=material['acme_key'],
                  config={'server': settings['acme_directory'], 'issuer': 'LETS_ENCRYPT'})
    dns = dict(asset, id=stable_id(company, 'dns-client'), name=company + ' Cloudflare DNS', type='CLOUDFLARE',
               config=json.dumps({'api_token': cloudflare_token, 'zone_id': settings['zone_id'],
                                  'account_id': settings.get('cloudflare_account_id')}))
    workflow = {'id': stable_id(company, 'workflow-' + cycle), 'account_id': account_id,
                'created_by': owner_id, 'updated_by': owner_id, 'groups': [group],
                'status': 'PENDING', 'state': 'ORDER_PENDING', 'scheduled': stamp,
                'date_created': stamp, 'date_updated': stamp, 'history': [],
                'acme_client_id': client['id'], 'dns_client_id': dns['id'], 'domains': domains,
                'standalone_automation_id': stable_id(company, 'certificate-automation'),
                'challenge_type': 'DNS_01', 'domain_key_pair': material['domain_key'],
                'algo': 'RSA', 'profile': 'shortlived', 'auto_renew': True, 'create_access_token': False,
                'has_error': False}
    return {'acme_clients': [client], 'dns_clients': [dns], 'acme_workflow': [workflow]}


def rehearsal_data(company, group, account_id, owner_id, bundle, run_id):
    """Exercise deployment of an already issued certificate; not new issuance."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', bundle, re.S)
    key = re.search(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----', bundle, re.S)
    if not blocks or not key:
        raise ValueError('An issued certificate and private key are required')
    leaf = x509.load_pem_x509_certificate(blocks[0].encode())
    def certificate_time(name):
        value = getattr(leaf, name + '_utc', None)
        if value is None:
            value = getattr(leaf, name).replace(tzinfo=timezone.utc)
        return value.replace(tzinfo=None).isoformat()
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    stamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')
    cert_id = stable_id(company, 'rehearsal-cert-' + leaf.fingerprint(hashes.SHA256()).hex())
    certificate = {'id': cert_id, 'account_id': account_id, 'created_by': owner_id, 'updated_by': owner_id,
                   'groups': [group], 'name': company + ' existing issued certificate rehearsal',
                   'status': 'ACTIVE', 'date_created': stamp, 'date_updated': stamp,
                   'primary_domain': sans[0], 'san_domains': sans,
                   'not_before': certificate_time('not_valid_before'),
                   'expires': certificate_time('not_valid_after'),
                   'public_cert': '\n'.join(blocks) + '\n', 'private_key': key.group(0) + '\n',
                   'fingerprint_sha256': leaf.fingerprint(hashes.SHA256()).hex(), 'entries': len(blocks)}
    queue = {'id': stable_id(company, 'rehearsal-' + run_id), 'account_id': account_id,
             'automation_id': stable_id(company, 'certificate-automation'), 'cert_id': cert_id,
             'type': 'CERTIFICATE', 'status': 'PENDING', 'date_created': stamp, 'date_updated': stamp}
    return {'certs': [certificate], 'acme_automation_queue': [queue]}


def schedule_existing_certificate(issued, certificate, now=None):
    """Reuse a validated short-lived certificate and renew a day before expiry.

    This only schedules a future workflow; it never submits an immediate order.
    Bundle chain, key and hostname validation is required by prepare_ingress.
    """
    now = now or datetime.now(timezone.utc)
    start = datetime.fromisoformat(certificate['not_before']).replace(tzinfo=timezone.utc)
    expires = datetime.fromisoformat(certificate['expires']).replace(tzinfo=timezone.utc)
    if not 159 <= (expires - start).total_seconds() / 3600 <= 161:
        raise ValueError('Certificate reuse requires an already issued shortlived certificate')
    scheduled = expires - timedelta(days=1)
    if scheduled <= now:
        raise ValueError('Certificate reuse requires more than one day of remaining validity')
    workflow = dict(issued['acme_workflow'][0], state='ORDER_SCHEDULED',
                    scheduled=scheduled.replace(tzinfo=None).isoformat(timespec='milliseconds'),
                    cert_id=certificate['id'])
    return workflow


def validate_reuse_source(company, trust):
    """Read and validate the company certificate before changing infrastructure."""
    from uncloud_support import prepare_ingress
    values = prepare_ingress(company, trust, allow_create=False, certificate=True)
    # Build only an in-memory validation fixture; no loader or write is invoked.
    certificate = rehearsal_data(company, 'validation', 'validation', 'validation',
                                  values['uncloud_ingress_pem'], 'validation')['certs'][0]
    renewal = schedule_existing_certificate({'acme_workflow': [{}]}, certificate)
    return {'expires': certificate['expires'], 'renewal_scheduled': renewal['scheduled']}
