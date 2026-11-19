"""Consume the Install Setup records created in the customer's hosted Trust account."""
import base64
import ipaddress
import json
import os
import re
import stat
import urllib.request
from dataclasses import dataclass
from urllib.parse import quote

from certlocker_gateway import GatewayRoutes, HOSTED_GATEWAY, operator_gateway
from uncloud_config import email
from uncloud_host_access import public_key
from uncloud_smtp import PASSWORD, validate
from uncloud_support import NoRedirect, Trust, ensure_certlocker_token, validate_master_key



def enroll_registry_file(company, trust, config, path):
    """Enroll an operator-supplied pull token in the selected install group."""
    if (not config.get('install_config_id') or trust.api_url != operator_gateway()
            or config.get('trust_account_id') != trust.routes.account_id
            or config.get('trust_group') != trust.group or config.get('registry_mode', 'ghcr') != 'ghcr'):
        raise ValueError('A hosted Trust Install setup for GHCR is required to enroll a pull token')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= 4096:
            raise ValueError('Use an owner-only regular file for the GitHub pull token')
        raw = stream.read(4097).strip()
    if not re.fullmatch(rb'ghp_[A-Za-z0-9]+', raw):
        raise ValueError('Expected one classic GitHub pull token in the supplied file')
    token = raw.decode('ascii')
    request = urllib.request.Request('https://api.github.com/user', headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'User-Agent': 'CertLocker-Installer'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            scopes = response.headers.get_all('X-OAuth-Scopes') or []
            if [s.strip() for header in scopes for s in header.split(',')] != ['read:packages']:
                raise ValueError('The GitHub token must have exactly the read:packages scope')
            try:
                account = json.loads(response.read(65536))
            except (UnicodeError, ValueError):
                raise ValueError('GitHub returned an invalid account response') from None
    except OSError:
        raise ValueError('GitHub could not verify the pull token; check its expiry and network access') from None
    username = account.get('login') if isinstance(account, dict) else None
    if not isinstance(username, str) or not re.fullmatch(r'[a-zA-Z0-9-]{1,39}', username):
        raise ValueError('GitHub did not return a usable account name')
    if config.get('ghcr_username', username).lower() != username.lower():
        raise ValueError('GitHub pull token account differs from the configured registry username')
    if trust.populate_empty(company, 'vault_cr_pat', token) != token:
        raise ValueError('This installation already has a different GHCR credential in Trust')
    config['ghcr_username'] = username


def connect(config, account_id, interactive):
    from uncloud_terminal import prompt_line
    saved = config.get('trust_account_id')
    account = account_id or saved or os.environ.get('CERTLOCKER_ACCOUNT_ID')
    if not account and interactive:
        account = prompt_line('Your account ID from Install setup at ' + operator_gateway())
    account = GatewayRoutes(account or '').account_id
    if saved and account != saved:
        raise ValueError('Account ID differs from the saved Trust installation')
    if not os.environ.get('CERTLOCKER_INSTALL_TRUST_URL') and os.environ.get('CERTLOCKER_API_URL', HOSTED_GATEWAY).rstrip('/') != HOSTED_GATEWAY:
        raise ValueError('Install setup requires the hosted Gateway at trust.certlocker.io')
    ensure_certlocker_token(interactive=interactive)
    trust = Trust(api_url=operator_gateway(), group=config.get('trust_group'), account_id=account)
    trust.check_authorization(config.get('company'), interactive=interactive)
    return trust


def fetch_object(trust, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', identifier):
        raise ValueError('Trust install setup has an invalid secret reference')
    raw = trust.request('api/v1/secret/fetch/' + quote(identifier, safe=''), plain=True)
    try:
        document = json.loads(raw)
    except (TypeError, ValueError):
        document = None
    if not isinstance(document, dict):
        raise ValueError('Trust install setup returned an invalid secret document')
    return document


def load_setup(trust, config, provider):
    name = trust.group + '_install_config'
    record = trust.lookup_metadata(name)
    if not record:
        raise ValueError('Install setup configuration is missing from this Trust group')
    identifier = record['id']
    if config.get('install_config_id', identifier) != identifier:
        raise ValueError('Trust install setup differs from the saved installation')
    setup = fetch_object(trust, identifier)
    types = ('GENERIC', 'AWS', 'AZURE', 'GCP') if provider == 'supplied' else (provider,)
    if setup.get('account_id') != trust.routes.account_id or setup.get('install_type') not in types:
        raise ValueError('Trust install setup account or provider differs from this installation')
    if not config.get('install_config_id') and setup.get('access_token') != trust.token:
        raise ValueError('Use the token returned by Install setup for this configuration')
    if not isinstance(setup.get('user_email'), str):
        raise ValueError('Missing user email in Trust install setup')
    admin = email(setup['user_email'])
    if provider == 'supplied' and 'server_ips' in setup and setup['install_type'] == 'GENERIC':
        addresses = setup['server_ips']
        if not isinstance(addresses, list) or len(addresses) != 2 or any(type(ip) is not str for ip in addresses):
            raise ValueError('Trust install setup must contain two server IPv4 addresses')
        try:
            addresses = [str(ipaddress.IPv4Address(ip)) for ip in addresses]
        except ValueError:
            raise ValueError('Trust install setup contains an invalid server IPv4 address') from None
        if addresses[0] == addresses[1]:
            raise ValueError('Trust install setup server IPv4 addresses must be distinct')
        config['server_ips'] = addresses
    if setup['install_type'] in ('GENERIC', 'GCP'):
        hostnames = setup.get('server_hostnames')
        if hostnames is not None:
            if (not isinstance(hostnames, list) or len(hostnames) != 2
                    or not all(isinstance(h, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', h)
                               for h in hostnames) or hostnames[0] == hostnames[1]):
                raise ValueError('Expected two distinct short hostnames in Trust Install setup')
            config['server_hostnames'] = hostnames
        for field in ('dns_zone', 'front_url', 'backoffice_url', 'grafana_url'):
            if setup.get(field) is not None:
                if not isinstance(setup[field], str) or not setup[field].strip():
                    raise ValueError('Invalid ' + field + ' in Trust Install setup')
                config[field] = setup[field]
        zone = config.get('dns_zone')
        label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if zone and (len(zone) > 253 or not re.fullmatch(label + r'(?:\.' + label + ')+', zone)):
            raise ValueError('Enter a DNS zone such as example.org')
        urls = [config[field].removesuffix('/') for field in ('front_url', 'backoffice_url', 'grafana_url') if config.get(field)]
        if len(set(urls)) != len(urls) or any(not zone or not re.fullmatch(
                'https://' + label + r'\.' + re.escape(zone), url) for url in urls):
            raise ValueError('Service URLs must be distinct HTTPS hostnames directly inside the DNS zone')
        options = setup.get('deployment_options') or {}
        if not isinstance(options, dict):
            raise ValueError('Invalid site settings in Trust Install setup')
        if options.get('deployment') is not None:
            if options['deployment'] not in ('dev', 'prod'):
                raise ValueError('Invalid deployment type in Trust Install setup')
            config['deployment'] = options['deployment']
        if options.get('admin_email'):
            admin = email(options['admin_email'])
        if options.get('acme_email'):
            config['acme_email'] = email(options['acme_email'])
        for field in ('account_domain', 'admin_display_name'):
            if options.get(field):
                config[field] = options[field]
        peers = options.get('peer_ips')
        if peers is not None:
            if not isinstance(peers, list) or len(peers) != 2 or peers[0] == peers[1]:
                raise ValueError('Trust must supply two distinct peer addresses')
            config['peer_ips'] = [str(ipaddress.IPv4Address(addr)) for addr in peers]
        if 'vpn_ips' in options:
            from uncloud_access import customer_cidrs
            config['vpn_from_setup'] = True
            config['vpn_cidrs'] = customer_cidrs(','.join(options['vpn_ips']))
        if 'ingress_cidrs' in options:
            networks = [ipaddress.IPv4Network(cidr, strict=False) for cidr in options['ingress_cidrs']]
            if any(network.prefixlen == 0 for network in networks):
                raise ValueError('Private ingress requires scoped source networks')
            config['ingress_cidrs'] = [str(network) for network in networks]
    config.update(trust_account_id=trust.routes.account_id, trust_group=trust.group,
                  install_config_id=identifier, initial_admin_email=admin)
    # The UI supplies the group token. Never export the embedded access_token or
    # forward the credential to a gateway_url obtained from a secret.
    return setup


def server_addresses(addresses, saved=(), prompt=None):
    """Use the Trust pair when available and retain positional inputs for older setups."""
    if saved:
        if any(given and given != expected for given, expected in zip(addresses, saved)):
            raise ValueError('Server IPv4 addresses differ from Trust Install setup')
        return tuple(saved)
    resolved = tuple(address or (prompt(label) if prompt else '') for address, label in zip(
        addresses, ('First Ubuntu server IPv4', 'Second Ubuntu server IPv4')))
    if not all(resolved):
        raise ValueError('Two server IPv4 addresses are required when Trust Install setup does not include them')
    resolved = tuple(str(ipaddress.IPv4Address(address)) for address in resolved)
    if resolved[0] == resolved[1]:
        raise ValueError('Two distinct machines are required')
    return resolved


def referenced_secret(trust, setup, field, suffix):
    record = trust.lookup_metadata(trust.group + suffix)
    if not record or record['id'] != setup.get(field):
        raise ValueError('Trust install setup secret reference differs from its group record')
    return fetch_object(trust, record['id'])


@dataclass(repr=False)
class InstallCredentials:
    master: str
    smtp_password: str
    pem: dict | None
    image_pull_token: str | None = None

    cloudflare_api_token: str | None = None
    admin_password: str | None = None

    def enroll(self, company, trust, *, allow_create=True):
        if trust.ensure(company, 'vault_certlocker_master_key', lambda: self.master, allow_create) != self.master:
            raise ValueError('Existing installation master key differs from Trust install setup')
        if allow_create:
            password = trust.populate_empty(company, PASSWORD, self.smtp_password)
        else:
            password = trust.ensure(company, PASSWORD, lambda: self.smtp_password, allow_create=False)
        if password != self.smtp_password:
            raise ValueError('Existing installation mail password differs from Trust install setup')


def read_ssh_identity(trust, setup):
    if setup.get('pem_secret_id') is None:
        raise ValueError('Supplied servers require an SSH identity in Trust install setup')
    pem = referenced_secret(trust, setup, 'pem_secret_id', '-ssh')
    user = pem.get('username')
    if not isinstance(user, str) or user == 'root' or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('Trust SSH identity requires a non-root Linux username')
    public = public_key(pem.get('key'), ed25519_only=False)
    return pem, public


def read_credentials(trust, config, provider):
    # Commit settings to the caller only once all referenced secrets validate.
    profile = {field: config[field] for field in ('install_config_id',) if field in config}
    setup = load_setup(trust, profile, provider)
    image_pull_token = None
    if 'image_pull_access' in setup:
        try:
            login = base64.b64decode(setup['image_pull_access'], validate=True).decode('ascii')
        except (ValueError, TypeError):
            login = ''
        identity = re.fullmatch(r'([A-Za-z0-9-]{1,39}):(ghp_[A-Za-z0-9]+)', login)
        if not identity:
            raise ValueError('Invalid release image access in the Trust install configuration')
        profile['ghcr_username'], image_pull_token = identity.groups()
    master = referenced_secret(trust, setup, 'master_key_secret_id', '-master-key').get('value')
    validate_master_key(master)
    mail = referenced_secret(trust, setup, 'email_secret_id', '-email')
    if mail.get('auth') not in ('true', 'false') or any(type(mail.get(flag)) is not bool for flag in ('start_tls', 'smtp_ssl')):
        raise ValueError('Invalid SMTP authentication or TLS settings in Trust install setup')
    try:
        port = int(mail['smtp_port'])
    except (TypeError, KeyError, ValueError):
        raise ValueError('Invalid SMTP port in Trust install setup') from None
    settings = dict(smtp_mode='customer', smtp_host=mail.get('smtp_host'), smtp_port=port,
                    smtp_tls='tls' if mail['smtp_ssl'] else ('starttls' if mail['start_tls'] else 'none'),
                    smtp_user=mail.get('smtp_username'), smtp_auth=mail['auth'] == 'true',
                    smtp_ssl_trust=mail.get('ssl_trust', '*'))
    validate(dict(settings, smtp_enabled=True))
    password = mail.get('smtp_password')
    if not isinstance(password, str) or not password:
        raise ValueError('Trust install setup is missing the SMTP password')

    pem = None
    if provider != 'GCP' or setup.get('pem_secret_id') is not None:
        pem, public = read_ssh_identity(trust, setup)
        if provider == 'GCP':
            profile['additional_ssh_key'] = pem['username'] + ':' + public
    if provider == 'GCP' and pem is None:
        config.pop('additional_ssh_key', None)
    cloudflare_token = None
    if setup.get('cloudflare_secret_id'):
        cloudflare_token = referenced_secret(trust, setup, 'cloudflare_secret_id', '-cloudflare').get('value')
        if not isinstance(cloudflare_token, str) or not cloudflare_token.strip():
            raise ValueError('Missing Cloudflare API token in the referenced Trust secret')
    admin_password = None
    if setup.get('admin_password_secret_id'):
        admin_password = referenced_secret(trust, setup, 'admin_password_secret_id', '-admin-password').get('value')
        if not isinstance(admin_password, str) or not admin_password:
            raise ValueError('Invalid initial administrator password in Trust')
    config.update(profile, **settings)
    return InstallCredentials(master, password, pem if provider == 'supplied' else None, image_pull_token, cloudflare_token, admin_password)
