"""Account-scoped Trust Gateway routes. No legacy routing or network probing."""
import os
import re


DEFAULT_ACCOUNT_ID = '2pc4im00jo'


HOSTED_GATEWAY = 'https://trust.certlocker.io/rest'


def operator_gateway(value=None):
    from urllib.parse import urlsplit
    url = (value or os.environ.get('CERTLOCKER_INSTALL_TRUST_URL') or HOSTED_GATEWAY).rstrip('/')
    parsed = urlsplit(url)
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.path.endswith(('/rest', '/rest/api'))
            or not (parsed.scheme == 'https' or (parsed.scheme == 'http'
                    and parsed.hostname in ('localhost', '127.0.0.1', '::1')))):
        raise ValueError('Use a Trust Gateway URL ending in /rest or /rest/api. HTTP requires localhost.')
    return url.removesuffix('/api')


class GatewayRoutes:
    def __init__(self, account_id=None, api_mode=None):
        self.account_id = (os.environ.get('CERTLOCKER_ACCOUNT_ID', DEFAULT_ACCOUNT_ID) if account_id is None else account_id).strip()
        mode = (api_mode or os.environ.get('CERTLOCKER_API_MODE') or 'account').strip().lower()
        if mode != 'account':
            raise ValueError('Only account-scoped Trust APIs are supported; remove CERTLOCKER_API_MODE or set it to account')
        if not self.account_id:
            raise ValueError('CERTLOCKER_ACCOUNT_ID is required')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', self.account_id):
            raise ValueError('Invalid CERTLOCKER_ACCOUNT_ID')

    def path(self, path):
        # Internal callers use resource-relative operations. All requests on the
        # wire include the account; explicitly scoped paths must match it.
        match = re.match(r'^(api/v1/(?:secret|cert|token))/([^/?]+)(.*)$', path)
        if not match:
            return path
        prefix, operation, suffix = match.groups()
        if operation in ('get', 'fetch', 'fetch-bundle', 'lookup', 'create', 'modify', 'revoke', 'hosts-available'):
            return prefix + '/' + self.account_id + '/' + operation + suffix
        if operation != self.account_id:
            raise ValueError('Gateway path account does not match the configured Trust account')
        return path

    def payload(self, body):
        if not isinstance(body, dict):
            return body
        # Both released naming conventions ignore unknown properties. Include
        # aliases at the asset level only; never rewrite the opaque secret value.
        result = dict(body)
        for snake, camel in [('secret_type', 'secretType')]:
            if snake in result:
                result[camel] = result[snake]
            elif camel in result:
                result[snake] = result[camel]
        return result
