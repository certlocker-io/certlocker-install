"""Shared company inventory, Trust and immutable release handling for HA commands."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import resource
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from certlocker_gateway import GatewayRoutes

ROOT = Path(__file__).resolve().parents[1]
# Non-secret record locator; the supplied Trust token must authorize reading it.
DEFAULT_GHCR_SECRET_NAME = 'ansible.dev04.certlocker_stack.vault_cr_pat'
MISSING = object()
WEB_SERVICES = ('ui', 'backoffice-ui')
API_SERVICES = ('dataservice', 'gateway', 'bastion-server', 'edge', 'backoffice-api', 'router')
MONITORING_SERVICES = ('node-exporter', 'cadvisor', 'postgres-exporter', 'alertmanager', 'google-chat-alerts', 'prometheus', 'loki', 'alloy', 'grafana')
GHCR_APPLICATION_REPOSITORIES = {'dataservice': 'ghcr.io/certlocker-io/trust/certlocker-dataservice', 'gateway': 'ghcr.io/certlocker-io/trust/certlocker-gateway', 'bastion-server': 'ghcr.io/certlocker-io/trust/certlocker-bastion-server', 'edge': 'ghcr.io/certlocker-io/trust/certlocker-edge', 'backoffice-api': 'ghcr.io/certlocker-io/trust/certlocker-backoffice', 'router': 'ghcr.io/certlocker-io/trust/certlocker-router', 'ui': 'ghcr.io/certlocker-io/ui-edge/cl-fe', 'backoffice-ui': 'ghcr.io/certlocker-io/ui-bo/cl-bo'}


def is_valid_trust_token(token):
    """Match Gateway TokenUtils.isValidToken without contacting Trust."""
    if not isinstance(token, str):
        return False
    token = token.strip()
    if not token or '-' not in token:
        return False
    if not 10 <= len(token) <= 75:
        return False
    if token.count('@') > 1 or token.startswith('@') or token.endswith('@'):
        return False
    return True


def ensure_certlocker_token(*, interactive=False, always_prompt=False):
    """Require a hidden Trust token or the CERTLOCKER_TOKEN / TRUST_TOKEN environment input."""
    from uncloud_terminal import prompt_secret

    current = (os.environ.get('CERTLOCKER_TOKEN') or os.environ.get('TRUST_TOKEN', '')).strip()
    if always_prompt:
        current = ''
    while True:
        if current and is_valid_trust_token(current):
            os.environ['CERTLOCKER_TOKEN'] = current
            return current
        os.environ.pop('CERTLOCKER_TOKEN', None)
        message = (
            'Invalid Trust token format; use a company deployment token from trust.certlocker.io.'
            if current else 'CERTLOCKER_TOKEN or TRUST_TOKEN is required for setup or Trust/DNS cleanup.'
        )
        if not interactive and not always_prompt:
            raise ValueError(message)
        if current:
            print(message, flush=True)
        print(
            'Paste the company Trust API token from trust.certlocker.io '
            '(not a Cloudflare token, Terminal SSH token, or Gmail App Password).',
            flush=True,
        )
        current = prompt_secret(
            'Company Trust deployment token (hidden)',
            env_name='CERTLOCKER_TOKEN',
        ).strip()


def normalize_version(value):
    if value == 'latest':
        return value
    value = value.removeprefix('prod_').removeprefix('v')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise ValueError('Version must be latest or a stable MAJOR.MINOR.PATCH version')
    return 'v' + value


SERVICE_ALIASES = {
    'bastion': 'bastion-server',
    'backoffice': 'backoffice-api',
    'bo': 'backoffice-api',
    'bo-api': 'backoffice-api',
    'bo-ui': 'backoffice-ui',
    'fe': 'ui',
}


def select_services(values=None):
    groups = {'apps': (*API_SERVICES, *WEB_SERVICES), 'web': WEB_SERVICES,
              'java': API_SERVICES, 'api': API_SERVICES, 'monitoring': MONITORING_SERVICES,
              'logs': ('loki', 'alloy')}
    selected = set()
    for value in values or ['apps']:
        for item in value.split(','):
            item = SERVICE_ALIASES.get(item, item)
            if item in groups:
                selected.update(groups[item])
            elif item in (*API_SERVICES, *WEB_SERVICES, *MONITORING_SERVICES):
                selected.add(item)
            else:
                raise ValueError('Unknown deployment component: ' + item)
    # A Router replacement loses its in-memory registry. All Java clients must
    # restart to register again, including clients whose image is unchanged.
    if 'router' in selected:
        selected.update(API_SERVICES)
    return [name for name in (*API_SERVICES, *WEB_SERVICES, *MONITORING_SERVICES) if name in selected]


def merge_release(current, candidate, selected):
    if set(current['services']) != set(candidate['services']):
        raise ValueError('Current and candidate manifests have different service sets')
    result = json.loads(json.dumps(current))
    for name in selected:
        result['services'][name] = candidate['services'][name]
    result['release'] = candidate['release']
    result['deployment_selection'] = list(selected)
    result['selection_source'] = {'release': candidate['release'],
                                'services': list(selected)}
    return result


def company_slug(value):
    value = value.lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', value):
        raise ValueError('Company must be a short alphanumeric/hyphen inventory slug')
    return value


DEPLOYMENTS = ('dev', 'prod')


def require_deployment(config):
    """Require an explicit customer deployment flag; migrate legacy lab configs to dev."""
    deployment = config.get('deployment')
    if deployment is None and config.get('environment') == 'isolated-uncloud-database-trial':
        deployment = 'dev'
        config['deployment'] = deployment
    if deployment not in DEPLOYMENTS:
        raise ValueError('deployment must be "dev" or "prod"')
    return deployment


def environment_config_path(root, company):
    """Preferred company environment file; accept legacy lab paths when present."""
    company = company_slug(company)
    modern = Path(root) / 'uncloud' / 'environments' / (company + '.json')
    if modern.exists():
        return modern
    for legacy in (
        Path(root) / 'uncloud' / 'lab' / (company + '.lab.json'),
        Path(root) / 'uncloud' / 'lab' / (company + '.json'),
    ):
        if legacy.exists():
            return legacy
    return modern


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(value)
    path.chmod(0o600)


def inventory_directory(company):
    return ROOT / 'inventory/uncloud' / company_slug(company)


def trust_name(company, variable):
    return f'ansible.uncloud.{company_slug(company)}.certlocker_stack.{variable}'


# Company-scoped deployment records created by setup. Never includes shared
# bootstrap secrets outside the customer account.
COMPANY_TRUST_VARIABLES = (
    'vault_certlocker_bootstrap_account',
    'vault_certlocker_ingress_settings',
    'vault_certlocker_application_settings',
    'vault_certlocker_certificate_settings',
    'vault_certlocker_certificate_identity',
    'vault_certlocker_database_identity',
    'vault_certlocker_postgres_password',
    'vault_certlocker_repmgr_password',
    'vault_certlocker_pgpool_admin_password',
    'vault_certlocker_postgres_replication_password',
    'vault_certlocker_postgres_backup_repo_cipher_pass',
    'vault_certlocker_postgres_backup_s3_access_key',
    'vault_certlocker_postgres_backup_s3_secret_key',
    'vault_certlocker_master_key',
    'vault_certlocker_stack_env_key',
    'vault_certlocker_company_name',
    'vault_certlocker_dataservice_smtp_pass',
    'vault_certlocker_landing_smtp_pass',
    'vault_certlocker_managed_smtp_settings',
    'vault_certlocker_managed_smtp_pass',
    'vault_certlocker_haproxy_acme_token',
    'vault_cloudflare_ini_key',
    'vault_grafana_admin_password',
    'vault_noc_google_chat_webhook_url',
    'vault_noc_slack_webhook_url',
    'vault_noc_slack_channel',
    'vault_cr_pat',
)

COMPANY_CERT_SUFFIXES = (
    'ca.ca.crt', 'ca.ca.key', 'ca.ca.srl',
    'postgres-primary.ca.crt', 'postgres-primary.server.crt', 'postgres-primary.server.key',
    'postgres-replica.ca.crt', 'postgres-replica.server.crt', 'postgres-replica.server.key',
)


def company_trust_record_names(company, extra_names=None):
    """Return every known company-owned Trust name for teardown."""
    company = company_slug(company)
    names = [trust_name(company, variable) for variable in COMPANY_TRUST_VARIABLES]
    names.extend(f'ansible.uncloud.{company}.certs.{suffix}' for suffix in COMPANY_CERT_SUFFIXES)
    names.append(f'ansible.uncloud.{company}.hosts.provisioning.ssh_key')
    for name in extra_names or ():
        if not isinstance(name, str) or not name.startswith(f'ansible.uncloud.{company}.'):
            raise ValueError('Trust teardown extras must belong to this company namespace')
        names.append(name)
    # Preserve order while dropping duplicates.
    return list(dict.fromkeys(names))


def discover_host_trust_names(company, *directories):
    """Collect host and successful-installation Trust names saved during setup."""
    company = company_slug(company)
    found = []
    for directory in directories:
        if not directory:
            continue
        path = Path(directory)
        candidates = []
        if path.is_file():
            candidates.append(path)
        else:
            candidates.extend(path.glob('host-access.json'))
            candidates.extend(path.glob('**/host-access.json'))
            candidates.extend(path.glob('**/installation-trust*.json'))
        for candidate in candidates:
            try:
                document = json.loads(candidate.read_text())
            except (OSError, ValueError):
                continue
            for key in ('ssh_key_record', 'host_inventory_record', 'installation_record'):
                name = document.get(key)
                if isinstance(name, str) and (name.startswith(f'ansible.uncloud.{company}.hosts.')
                        or key == 'installation_record' and name.startswith(f'ansible.uncloud.{company}.installations.')):
                    found.append(name)
    return list(dict.fromkeys(found))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TrustAuthorizationError(RuntimeError):
    """A rejected credential, reported without exposing the response or token."""


def invalid_token_response(error):
    """Recognize Gateway's token rejection without displaying arbitrary server text."""
    try:
        value = error.read(4096).decode('utf-8')
        try:
            value = json.loads(value)
        except ValueError:
            pass
        if isinstance(value, dict):
            value = value.get('message', value.get('error'))
        return isinstance(value, str) and value.strip().lower() in (
            'invalid token', 'invalid token.', 'token is invalid',
        )
    except (OSError, UnicodeError):
        return False


class Trust:
    """Use the same Gateway get/fetch and CONFIGURATION value wrapper as the collection.

    Deliberately do not include server response bodies in exceptions or reports.
    Values and the deployment token exist only in memory, never command arguments.
    """
    def __init__(self, api_url=None, token=None, group=None, account_id=None, api_mode=None):
        self.routes = GatewayRoutes(account_id, api_mode)
        self.api_url = (api_url or os.environ.get('CERTLOCKER_API_URL') or
                        'https://trust.certlocker.io/rest').rstrip('/')
        if urllib.parse.urlsplit(self.api_url).scheme != 'https':
            raise ValueError('Trust deployment access requires verified HTTPS')
        self.token = token or os.environ.get('CERTLOCKER_TOKEN', '').strip()
        if not self.token:
            raise ValueError('CERTLOCKER_TOKEN is required for company Trust deployment records')
        self.group = group
        if group is not None and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}', group):
            raise ValueError('Invalid company Trust group')

    def check_authorization(self, company, *, interactive=False):
        """Retry rejected tokens during the read-only preflight, before provisioning."""
        while True:
            try:
                self.get(trust_name(company, 'vault_certlocker_company_name'))
                return
            except TrustAuthorizationError as error:
                if not interactive:
                    raise
                print(str(error), flush=True)
                self.token = ensure_certlocker_token(interactive=True, always_prompt=True)

    def bind_account(self, company, expected, marker_id):
        """Bind a customer token before reading or creating any actual credential.

        Group-scoped creation is not enforced by the released Gateway. Customer
        delivery therefore requires an operator-provisioned isolated account.
        The Gateway omits account IDs from secret metadata. Pin a marker's
        server-assigned ID before customer delivery instead. The customer path
        never creates its own marker. Account ID is operator-attested metadata;
        this check cannot prove the operator kept the account isolated.
        """
        if not isinstance(expected, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', expected):
            raise ValueError('Customer delivery requires the dedicated Trust account ID')
        if not self.group:
            raise ValueError('Customer delivery requires an exact company Trust group')
        if not isinstance(marker_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', marker_id):
            raise ValueError('Customer delivery requires a pre-provisioned Trust account marker ID')
        name = trust_name(company, 'vault_certlocker_bootstrap_account')
        path = 'api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe='')
        document = self.request(path, missing=True)
        if not isinstance(document, dict) or not document.get('id'):
            raise ValueError('Dedicated customer Trust account binding is missing')
        actual = document.get('account_id', document.get('accountId'))
        if (document['id'] != marker_id or document.get('name') != name or
                document.get('groups') != [self.group] or (actual is not None and actual != expected)):
            raise ValueError('Deployment token does not match the dedicated customer Trust account and group')
        payload = self.request('api/v1/secret/fetch/' + urllib.parse.quote(marker_id, safe=''), plain=True)
        try:
            matches = json.loads(payload) == {'value': {'company': company, 'account_id': expected}}
        except (ValueError, TypeError):
            matches = False
        if not matches:
            raise ValueError('Dedicated customer Trust account marker contents do not match the delivery')

    def prepare_account_marker(self, company, expected):
        """Operator-only enrollment in an already isolated company account."""
        company = company_slug(company)
        if not isinstance(expected, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', expected):
            raise ValueError('A dedicated customer Trust account ID is required')
        if not self.group:
            raise ValueError('An exact company Trust group is required')
        variable = 'vault_certlocker_bootstrap_account'
        desired = {'company': company, 'account_id': expected}
        if self.ensure(company, variable, lambda: desired) != desired:
            raise ValueError('Existing account marker differs; refusing to overwrite it')
        name = trust_name(company, variable)
        document = self.request('api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''))
        if not isinstance(document, dict) or not document.get('id'):
            raise ValueError('Account marker creation could not be verified')
        self.bind_account(company, expected, document['id'])
        return document['id']

    def request(self, path, body=None, plain=False, missing=False):
        path = self.routes.path(path)
        body = self.routes.payload(body)
        headers = {'x-api-token': self.token, 'User-Agent': 'CertLocker-Ansible-Uploader/1.0',
                   'Accept': 'text/plain' if plain else 'application/json',
                   'Content-Type': 'text/plain' if plain else 'application/json'}
        request = urllib.request.Request(self.api_url + '/' + path,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers=headers, method='POST' if body is not None else 'GET')
        for attempt in range(8):
            try:
                with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                    value = response.read().decode()
                break
            except urllib.error.HTTPError as error:
                if missing and error.code == 404:
                    return None
                if error.code == 429 and attempt < 7:
                    # Explicit rate-limit rejections can be retried. Timeouts and
                    # other uncertain writes still use ensure's read-back path.
                    delay = error.headers.get('Retry-After', '')
                    time.sleep(min(float(delay) if delay.isdigit() else 2 ** (attempt + 1), 30))
                    continue
                # Other HTTP 400 responses can be request validation failures.
                if error.code == 400 and invalid_token_response(error):
                    raise TrustAuthorizationError(
                        'Invalid Trust token (HTTP 400). Enter a company deployment '
                        'token from trust.certlocker.io.'
                    ) from None
                if error.code == 401:
                    raise TrustAuthorizationError(
                        'Trust token was rejected (HTTP 401); it may be invalid, expired '
                        'or revoked. Enter an active company deployment token.'
                    ) from None
                if error.code == 403:
                    raise TrustAuthorizationError(
                        'Trust access denied (HTTP 403); check that the deployment '
                        'token has permission for this account, group and record.'
                    ) from None
                raise RuntimeError(f'Trust {request.method} failed (HTTP {error.code}); response suppressed') from None
            except (OSError, ValueError):
                raise RuntimeError('Trust connection failed; response suppressed') from None
        if missing and not value.strip():
            return None
        try:
            return value if plain else json.loads(value)
        except json.JSONDecodeError:
            raise RuntimeError('Trust returned an invalid configuration response; body suppressed') from None

    def get(self, name):
        document = self.request('api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''), missing=True)
        if document is None:
            return MISSING
        if isinstance(document, dict) and 'id' not in document:
            document = next((document[key] for key in ('secrets', 'items', 'contents', 'data', 'results')
                             if isinstance(document.get(key), list)), document)
        if isinstance(document, list):
            if not document:
                return MISSING
            if len(document) != 1:
                raise ValueError(f'Trust name must identify exactly one record: {name}')
            document = document[0]
        if not isinstance(document, dict) or not document.get('id'):
            raise ValueError(f'Trust lookup returned no usable record identity: {name}')
        identifier = urllib.parse.quote(str(document['id']), safe='')
        value = self.request('api/v1/secret/fetch/' + identifier, plain=True)
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
        if isinstance(value, dict) and isinstance(value.get('key'), str) and 'username' in value:
            return value['key']
        if not isinstance(value, dict) or 'value' not in value:
            raise ValueError(f'Trust configuration record has an unexpected format: {name}')
        return value['value']

    def ensure(self, company, variable, factory, allow_create=True):
        name = trust_name(company, variable)
        return self.ensure_named(name, company, factory, allow_create)

    def populate_empty(self, company, variable, value):
        """Populate only an empty, company-owned placeholder; never rotate a value.

        The Gateway has no update endpoint. Revoke the verified empty placeholder
        before creating its replacement so name lookup remains unambiguous.
        """
        name = trust_name(company, variable)
        existing = self.get(name)
        if existing is not MISSING and existing != '':
            return existing
        if not isinstance(value, str) or not value:
            raise ValueError('A populated integration credential is required')
        if existing == '':
            metadata = self.request('api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''))
            if not isinstance(metadata, dict) or metadata.get('name') != name or not metadata.get('id'):
                raise ValueError('Cannot identify the company-owned empty placeholder safely')
            identifier = urllib.parse.quote(str(metadata['id']), safe='')
            payload = self.request('api/v1/secret/fetch/' + identifier, plain=True)
            if json.loads(payload) != {'value': ''}:
                raise ValueError('Placeholder changed; refusing to replace an existing credential')
            self.request('api/v1/secret/revoke/' + identifier, {})
            if self.get(name) is not MISSING:
                raise RuntimeError('Empty placeholder revocation not confirmed; no duplicate will be created')
        return self.ensure(company, variable, lambda: value)

    def ensure_named(self, name, company, factory, allow_create=True, secret_type='CONFIGURATION', username=None):
        value = self.get(name)
        if value is not MISSING:
            return value
        if not allow_create:
            raise ValueError(f'Trust record missing for existing database; refusing credential regeneration: {name}')
        value = factory()
        payload = {'name': name, 'description': f'{company} HA deployment {name.rsplit(".", 1)[-1]}',
                   'secret_type': secret_type, 'secret': json.dumps({'username': username or company, 'key': value} if secret_type == 'PEM' else {'value': value}),
                   'groups': [self.group or company]}
        try:
            self.request('api/v1/secret/create', payload)
        except RuntimeError:
            # A create timeout is uncertain. Read back once; never replay create.
            existing = self.get(name)
            if existing is MISSING:
                raise
            return existing
        existing = self.get(name)
        if existing is MISSING:
            raise RuntimeError(f'Trust creation could not be verified: {name}')
        return existing

    def lookup_metadata(self, name):
        document = self.request('api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''), missing=True)
        if document is None:
            return None
        if isinstance(document, dict) and 'id' not in document:
            document = next((document[key] for key in ('secrets', 'items', 'contents', 'data', 'results')
                             if isinstance(document.get(key), list)), document)
        if isinstance(document, list):
            if not document:
                return None
            if len(document) != 1:
                raise ValueError(f'Trust name must identify exactly one record: {name}')
            document = document[0]
        if not isinstance(document, dict) or not document.get('id'):
            return None
        if document.get('name') not in (None, name):
            raise ValueError(f'Trust lookup returned a different name for {name}')
        return document

    def revoke_named(self, name):
        """Revoke one company Trust record by exact name; no-op when already absent."""
        metadata = self.lookup_metadata(name)
        if metadata is None:
            return 'absent'
        if metadata.get('name') not in (None, name):
            raise ValueError(f'Refusing to revoke a Trust record that does not match {name}')
        identifier = urllib.parse.quote(str(metadata['id']), safe='')
        try:
            self.request('api/v1/secret/revoke/' + identifier, {})
        except RuntimeError:
            if self.lookup_metadata(name) is None:
                return 'revoked'
            raise
        if self.lookup_metadata(name) is not None:
            raise RuntimeError(f'Trust revocation not confirmed for {name}')
        return 'revoked'


def revoke_company_trust(company, trust, extra_names=None, progress=None):
    """Revoke every known company-owned Trust secret for a destroyed environment."""
    company = company_slug(company)
    names = company_trust_record_names(company, extra_names)
    evidence = {'company': company, 'revoked': [], 'absent': [], 'failed': []}
    for name in names:
        short = name.rsplit('.', 1)[-1]
        if progress is not None:
            progress.detail('Revoking Trust record: ' + short)
        try:
            status = trust.revoke_named(name)
        except (RuntimeError, ValueError) as error:
            evidence['failed'].append({'name': short, 'error_type': type(error).__name__})
            continue
        evidence[status].append(short)
    if evidence['failed']:
        raise RuntimeError('Trust teardown could not revoke '
                           + ', '.join(item['name'] for item in evidence['failed']))
    return evidence


def set_ingress_names(company, trust, hostname, backoffice_hostname, grafana_hostname=None):
    """Explicitly change a company's non-secret ingress names during provisioning.

    Gateway exposes create/revoke, not update. Read back each uncertain operation;
    never rotate credential records or blindly replay a create.
    """
    grafana_hostname = grafana_hostname or 'grafana-cl.' + hostname.split('.', 1)[1]
    desired = {'hostname': hostname, 'backoffice_hostname': backoffice_hostname,
               'grafana_hostname': grafana_hostname}
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) for value in desired.values()):
        raise ValueError('Invalid ingress hostname')
    variable = 'vault_certlocker_ingress_settings'
    return replace_configuration(company, trust, variable, desired)


def replace_configuration(company, trust, variable, desired, *, allow_smtp_refresh=False):
    """Replace only the two non-secret company configuration records."""
    if variable not in ('vault_certlocker_ingress_settings', 'vault_certlocker_application_settings'):
        raise ValueError('Credential records cannot use configuration replacement')
    name = trust_name(company, variable)
    previous = trust.get(name)
    if previous == desired:
        return desired
    if previous is not MISSING:
        ingress_extension = (variable == 'vault_certlocker_ingress_settings' and isinstance(previous, dict)
                             and isinstance(desired, dict) and
                             set(previous) == {'hostname', 'backoffice_hostname'} and
                             set(desired) == set(previous) | {'grafana_hostname'} and
                             all(desired[key] == previous[key] for key in previous))
        smtp_extension = (variable == 'vault_certlocker_application_settings' and isinstance(previous, dict)
                          and isinstance(desired, dict) and set(previous).issubset(desired)
                          and set(desired) - set(previous) <= {'smtp_port', 'smtp_tls', 'smtp_mode'})
        smtp_refresh = (
            allow_smtp_refresh and variable == 'vault_certlocker_application_settings'
            and isinstance(previous, dict) and isinstance(desired, dict)
            and previous.get('public_url') == desired.get('public_url')
            and previous.get('ghcr_username') == desired.get('ghcr_username')
        )
        if not isinstance(previous, dict) or (
                set(previous) != set(desired) and not (smtp_extension or ingress_extension or smtp_refresh)):
            raise ValueError('Unexpected existing company ingress configuration')
        metadata = trust.request('api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''))
        if not isinstance(metadata, dict) or metadata.get('name') != name or not metadata.get('id'):
            raise ValueError('Cannot identify company ingress configuration safely')
        identifier = urllib.parse.quote(str(metadata['id']), safe='')
        payload = trust.request('api/v1/secret/fetch/' + identifier, plain=True)
        if json.loads(payload) != {'value': previous}:
            raise ValueError('Ingress configuration changed concurrently; refusing replacement')
        try:
            trust.request('api/v1/secret/revoke/' + identifier, {})
        except RuntimeError:
            if trust.get(name) is not MISSING:
                raise
        if trust.get(name) is not MISSING:
            raise RuntimeError('Ingress configuration revocation not confirmed')
    try:
        saved = trust.ensure(company, variable, lambda: desired)
    except RuntimeError:
        if previous is not MISSING and trust.get(name) is MISSING:
            trust.ensure(company, variable, lambda: previous)
        raise
    if saved != desired:
        raise ValueError('Ingress name read-back differs from the requested configuration')
    return saved


def prepare_ingress(company, trust, allow_create=True, certificate=True):
    settings = trust.ensure(company, 'vault_certlocker_ingress_settings', lambda: {
        'hostname': company + '.certlocker.io',
        'backoffice_hostname': 'backoffice-' + company + '.certlocker.io',
        'grafana_hostname': 'grafana-cl.' + company + '.certlocker.io'}, allow_create)
    required = {'hostname', 'backoffice_hostname', 'grafana_hostname'}
    if isinstance(settings, dict) and {'hostname', 'backoffice_hostname'} == set(settings):
        if not allow_create:
            settings = dict(settings, grafana_hostname='grafana-cl.' + settings['hostname'].split('.', 1)[1])
        else:
            settings = replace_configuration(company, trust, 'vault_certlocker_ingress_settings',
                dict(settings, grafana_hostname='grafana-cl.' + settings['hostname'].split('.', 1)[1]))
    if not isinstance(settings, dict) or set(settings) != required:
        raise ValueError('Trust ingress settings require hostname, backoffice_hostname, and grafana_hostname')
    for hostname in settings.values():
        if not isinstance(hostname, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', hostname):
            raise ValueError('Invalid ingress hostname')
    if not certificate:
        return {'uncloud_ingress_settings': settings}
    variable = 'vault_certlocker_haproxy_acme_token'
    token = trust.get(trust_name(company, variable))
    needs_population = token is MISSING or token == ''
    if needs_population:
        if not allow_create:
            raise ValueError('Company ingress certificate token has not been populated')
        source = os.environ.get('CERTLOCKER_ACME_SECRET_NAME')
        if not source:
            raise ValueError('Populate the company Trust ACME token or set CERTLOCKER_ACME_SECRET_NAME to its bootstrap source')
        token = trust.get(source)
    if not isinstance(token, str) or not token.strip():
        raise ValueError('Certificate source must contain an issued Trust certificate token')
    loader = importlib.machinery.SourceFileLoader('uncloud_certificates', str(ROOT / 'scripts/certlocker-fetch-haproxy-pem.py'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    helper = importlib.util.module_from_spec(spec)
    loader.exec_module(helper)
    raw = trust.request('api/v1/cert/fetch-bundle/' + urllib.parse.quote(token, safe=''), plain=True).encode()
    try:
        for hostname in settings.values():
            raw = helper.validate_bundle(raw, hostname)
    except helper.FetchError as error:
        raise ValueError(str(error)) from None
    # Validate both names and key correspondence before changing any placeholder.
    if needs_population:
        trust.populate_empty(company, variable, token)
    return {'uncloud_ingress_settings': settings, 'uncloud_ingress_pem': raw.decode()}


def prepare_trust(company, trust, allow_create=True, master_key=None, ghcr_username=''):
    ingress = trust.get(trust_name(company, 'vault_certlocker_ingress_settings'))
    public_url = 'http://localhost:3080'
    if isinstance(ingress, dict) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', ingress.get('hostname', '')):
        public_url = 'https://' + ingress['hostname']
    if master_key is not None:
        validate_master_key(master_key)
        existing = trust.get(trust_name(company, 'vault_certlocker_master_key'))
        if existing is not MISSING and existing != master_key:
            raise ValueError('Supplied master key differs from the existing company Trust key; refusing rotation')
    factories = {
        'vault_certlocker_postgres_password': lambda: secrets.token_hex(32),
        'vault_certlocker_repmgr_password': lambda: secrets.token_hex(32),
        'vault_certlocker_pgpool_admin_password': lambda: secrets.token_hex(32),
        'vault_certlocker_master_key': lambda: master_key or base64.b64encode(secrets.token_bytes(32)).decode(),
        'vault_certlocker_stack_env_key': lambda: secrets.token_hex(32),
        'vault_certlocker_company_name': lambda: company,
        'vault_certlocker_application_settings': lambda: {
            'public_url': public_url, 'smtp_host': '', 'smtp_user': '',
            'smtp_enabled': False, 'ghcr_username': ghcr_username},
        'vault_certlocker_dataservice_smtp_pass': lambda: '',
    }
    for variable, factory in factories.items():
        value = trust.ensure(company, variable, factory, allow_create)
        if variable.endswith('_password') or variable in ('vault_certlocker_master_key', 'vault_certlocker_stack_env_key'):
            if not isinstance(value, str) or not value:
                raise ValueError(f'Trust record must contain a nonempty string: {variable}')
        if variable == 'vault_certlocker_stack_env_key' and len(value) < 32:
            raise ValueError('Company Trust stack environment key must contain at least 32 characters')
        if variable == 'vault_certlocker_company_name' and value != company:
            raise ValueError('Trust company identity does not match the requested inventory')
        if variable == 'vault_certlocker_master_key':
            validate_master_key(value)
        if variable == 'vault_certlocker_application_settings':
            required = {'public_url', 'smtp_host', 'smtp_user', 'smtp_enabled', 'ghcr_username'}
            if not isinstance(value, dict) or not required.issubset(value) or not isinstance(value['smtp_enabled'], bool):
                raise ValueError('Company Trust application settings are incomplete or invalid')
            if allow_create and value['public_url'] == 'http://localhost:3080' and public_url != value['public_url']:
                replace_configuration(company, trust, variable, dict(value, public_url=public_url))
    return list(factories)


def validate_master_key(value):
    try:
        valid = len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError('Company Trust master key must encode exactly 32 bytes')


def _shared_optional_secret(trust, name):
    """Read a shared operator Trust secret; empty when absent or blank."""
    value = trust.get(name)
    if not isinstance(value, str):
        return ''
    return value.strip()


def initialize_environment(company, trust, allow_create=True, master_key=None, registry_mode='ghcr', ghcr_secret_name=None, ghcr_username='sean-certlocker'):
    """The init-new-environment contract, using create-once Trust operations.

    External integrations remain disabled when their optional credentials are
    empty. Optional integrations use only company-owned Trust records.
    """
    variables = prepare_trust(company, trust, allow_create, master_key,
                              ghcr_username=ghcr_username if registry_mode == 'ghcr' else '')
    factories = {
        'vault_grafana_admin_password': lambda: secrets.token_urlsafe(24),
        'vault_certlocker_postgres_replication_password': lambda: trust.get(trust_name(company, 'vault_certlocker_repmgr_password')),
        'vault_certlocker_postgres_backup_repo_cipher_pass': lambda: secrets.token_urlsafe(32),
        'vault_certlocker_postgres_backup_s3_access_key': lambda: '',
        'vault_certlocker_postgres_backup_s3_secret_key': lambda: '',
        'vault_certlocker_landing_smtp_pass': lambda: '',
        'vault_cloudflare_ini_key': lambda: '',
        'vault_noc_google_chat_webhook_url': lambda: '',
        'vault_noc_slack_webhook_url': lambda: '',
        'vault_noc_slack_channel': lambda: '',
        # An empty value marks ingress enrollment as pending. A random string is
        # not a valid issued ACME/certificate credential.
        'vault_certlocker_haproxy_acme_token': lambda: '',
    }
    if registry_mode == 'ghcr':
        def registry():
            source = ghcr_secret_name or os.environ.get('CERTLOCKER_GHCR_SECRET_NAME') or DEFAULT_GHCR_SECRET_NAME
            value = trust.get(source)
            if not isinstance(value, str) or not value.strip():
                raise ValueError('GHCR pull credential is missing or empty in Trust')
            return value
        factories['vault_cr_pat'] = registry
        settings_name = 'vault_certlocker_application_settings'
        settings = trust.get(trust_name(company, settings_name))
        if not settings.get('ghcr_username'):
            if not allow_create:
                raise ValueError('Company GHCR username has not been configured in Trust')
            replace_configuration(company, trust, settings_name, dict(settings, ghcr_username=ghcr_username))
    elif registry_mode != 'gcp':
        raise ValueError('Unknown registry authentication mode')
    for variable, factory in factories.items():
        value = trust.ensure(company, variable, factory, allow_create)
        if variable == 'vault_cr_pat' and (not isinstance(value, str) or not value.strip()):
            raise ValueError('Company GHCR pull credential is empty')
    return variables + list(factories)


def replace_empty_database_record(trust, company, name, desired, secret_type='CONFIGURATION'):
    """Called only after the installer verifies that both DB volumes are absent."""
    current = trust.get(name)
    if current == desired:
        return desired
    if current is not MISSING:
        metadata = trust.request('api/v1/secret/lookup?name=' + urllib.parse.quote(name, safe=''))
        if not isinstance(metadata, dict) or metadata.get('name') != name or not metadata.get('id'):
            raise ValueError('Cannot identify the previous database TLS record safely')
        if trust.get(name) != current:
            raise ValueError('Database TLS record changed during replacement')
        identifier = urllib.parse.quote(str(metadata['id']), safe='')
        try:
            trust.request('api/v1/secret/revoke/' + identifier, {})
        except RuntimeError:
            if trust.get(name) is not MISSING:
                raise
        if trust.get(name) is not MISSING:
            raise RuntimeError('Database TLS revocation not confirmed')
    saved = trust.ensure_named(name, company, lambda: desired, secret_type=secret_type)
    if saved != desired:
        raise ValueError('Database TLS replacement could not be verified')
    return saved


def initialize_database_identity(company, trust, addresses, allow_create=True, allow_reissue=False):
    loader = importlib.machinery.SourceFileLoader('uncloud_identity_init', str(ROOT / 'playbooks/ops/files/uncloud_identity.py'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    passwords = {short: trust.get(trust_name(company, variable)) for short, variable in {
        'postgres': 'vault_certlocker_postgres_password', 'repmgr': 'vault_certlocker_repmgr_password',
        'pgpool': 'vault_certlocker_pgpool_admin_password'}.items()}
    if not all(isinstance(value, str) and value for value in passwords.values()):
        raise ValueError('Database credentials must exist before TLS initialization')
    bundle = trust.ensure(company, 'vault_certlocker_database_identity',
                          lambda: module.generate_bundle(addresses, passwords), allow_create)
    if bundle['addresses'] != addresses or bundle['passwords'] != passwords:
        if not (allow_create and allow_reissue):
            raise ValueError('Trust database identity differs from the mesh or passwords; refusing rotation')
        bundle = replace_empty_database_record(trust, company,
                    trust_name(company, 'vault_certlocker_database_identity'),
                    module.generate_bundle(addresses, passwords))
    # Stable names matching init-new-environment's certificate inventory layout.
    values = {'ca.ca.crt': bundle['ca'], 'ca.ca.key': bundle['ca_key'], 'ca.ca.srl': bundle['ca_serial']}
    for alias, node in zip(('postgres-primary', 'postgres-replica'), sorted(bundle['nodes'])):
        values.update({alias + '.ca.crt': bundle['ca'], alias + '.server.crt': bundle['nodes'][node]['certificate'],
                       alias + '.server.key': bundle['nodes'][node]['key']})
    for suffix, value in values.items():
        name = f'ansible.uncloud.{company_slug(company)}.certs.{suffix}'
        if allow_create and allow_reissue:
            saved = replace_empty_database_record(trust, company, name, value,
                        'PEM' if suffix.endswith('.key') else 'CONFIGURATION')
        else:
            saved = trust.ensure_named(name, company,
                                   lambda value=value: value, allow_create,
                                   secret_type='PEM' if suffix.endswith('.key') else 'CONFIGURATION')
        if saved != value:
            raise ValueError('Existing Trust certificate record differs from company identity: ' + suffix)
    return 'vault_certlocker_database_identity'


def read_master_key(path):
    if path.stat().st_mode & 0o077:
        raise ValueError('The master-key input file must be accessible only to its owner')
    value = path.read_text().strip()
    validate_master_key(value)
    return value


def write_trust_references(company, directory, variables, api_url):
    refs = {'certlocker_api_url': api_url, 'certlocker_api_profile': 'gateway'}
    for variable in variables:
        refs[variable] = "{{ (lookup('env', 'CERTLOCKER_DEPLOYMENT_VALUES') | from_json)[" + repr(variable) + "] }}"
    write_private(directory / 'group_vars/uncloud/trust.json', json.dumps(refs, indent=2) + '\n')


def resolve_environment(company, trust, variables):
    values = {}
    for variable in variables:
        value = trust.get(trust_name(company, variable))
        if value is MISSING:
            raise ValueError('Required company Trust record is missing: ' + variable)
        values[variable] = value
    return values


def run_ansible(command, values, require_no_swap=False):
    """Pass a named Trust snapshot through the child environment, never argv/files.

    Ansible resolves descriptor paths before opening them, so anonymous pipes are
    unsuitable for extra-vars files. Arguments contain only env lookup templates.
    """
    payload = json.dumps(values)
    if len(payload.encode()) > 120000:
        raise ValueError('Company configuration exceeds the in-memory environment transfer limit')
    references = {name: "{{ (lookup('env', 'CERTLOCKER_DEPLOYMENT_VALUES') | from_json)[" + repr(name) + "] }}"
                  for name in values}
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    memory = Path('/dev/shm')
    filesystem = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(memory)],
                                capture_output=True, text=True, check=True).stdout.strip()
    if filesystem != 'tmpfs':
        raise ValueError('Ansible secret rendering requires a tmpfs controller temporary directory')
    from uncloud_preflight import controller_swap_disabled
    if require_no_swap and not controller_swap_disabled():
        raise ValueError('Disable controller swap before transferring installation secrets')
    with tempfile.TemporaryDirectory(prefix='certlocker-ansible-', dir=memory) as temporary:
        subprocess.run([*map(str, command), '-e', json.dumps(references)],
                       cwd=ROOT, stdin=subprocess.DEVNULL,
                       env=dict(os.environ, CERTLOCKER_DEPLOYMENT_VALUES=payload,
                                ANSIBLE_LOCAL_TEMP=temporary, ANSIBLE_REMOTE_TMP=temporary,
                                ANSIBLE_DEBUG='false',
                                ANSIBLE_KEEP_REMOTE_FILES='false'), check=True)


def application_repositories(registry_prefix=None):
    if registry_prefix:
        if not re.fullmatch(r'[a-z0-9-]+-docker\.pkg\.dev/[a-z][a-z0-9-]{4,28}[a-z0-9]/[a-z0-9][a-z0-9_-]*', registry_prefix):
            raise ValueError('Expected a customer Artifact Registry repository prefix')
        return {service: registry_prefix + '/' + service for service in (*API_SERVICES, *WEB_SERVICES)}
    return dict(GHCR_APPLICATION_REPOSITORIES)


def validate_release_manifest(manifest, registry_prefix=None):
    services = (*API_SERVICES, *WEB_SERVICES)
    if not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'release', 'services'}:
        raise ValueError('Release manifests contain only schema_version, release and services; supply tokens through the hidden prompt or environment')
    if manifest.get('schema_version') != 1 or set(manifest.get('services', {})) != set(services):
        raise ValueError('Release manifest must contain exactly the eight application services')
    release = manifest.get('release', '')
    if re.fullmatch(r'prod_[0-9]+\.[0-9]+\.[0-9]+', release):
        pass
    else:
        raise ValueError('Expected a stable production release identifier')
    repositories = application_repositories(registry_prefix)
    for service, item in manifest['services'].items():
        if not isinstance(item, dict) or set(item) != {'image', 'version'} or not re.fullmatch(re.escape(repositories[service]) + r'@sha256:[0-9a-f]{64}', item.get('image', '')):
            raise ValueError('Unexpected image repository or mutable image for ' + service)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', item.get('version', '')):
            raise ValueError('Expected embedded build version for ' + service)
    return manifest


def bundled_release_manifest(path, release='latest', registry_prefix=None):
    path = Path(path)
    raw = path.read_bytes()
    digest = path.with_suffix(path.suffix + '.sha256').read_text().split()[0]
    if not re.fullmatch(r'[0-9a-f]{64}', digest) or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Bundled release manifest checksum does not match')
    manifest = validate_release_manifest(json.loads(raw), registry_prefix)
    if not re.fullmatch(r'prod_[0-9]+\.[0-9]+\.[0-9]+', manifest.get('release', '')):
        raise ValueError('Bundled release must be a stable production identifier')
    tag = 'v' + manifest['release'].removeprefix('prod_')
    if normalize_version(release) not in ('latest', tag):
        raise ValueError('Bundled release does not match --version')
    return manifest, {'tag': tag, 'sha256': digest}


def release_manifest(*args, **kwargs):
    raise ValueError('Supply the CertLocker release manifest and checksum')
