#!/usr/bin/env python3
"""Google VM identity access with no service-account key or token cache."""
import base64
import json
import re
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Credential endpoint redirects are forbidden')


def request(url, headers, data=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=20) as response:
            return response.read(1048576)
    except Exception:
        raise RuntimeError('Google credential operation failed; response suppressed') from None


def access_token(service_account):
    if not re.fullmatch(r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com', service_account):
        raise ValueError('Expected an explicitly configured VM service account')
    endpoint = 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/'
    headers = {'Metadata-Flavor': 'Google'}
    if request(endpoint + 'email', headers).decode().strip() != service_account:
        raise ValueError('Attached VM service account differs from installation configuration')
    token = json.loads(request(endpoint + 'token', headers))
    if token.get('token_type', '').lower() != 'bearer' or token.get('expires_in', 0) < 60:
        raise ValueError('VM identity token is unavailable or expiring')
    return token['access_token']


def validate_key(key):
    if not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+', key):
        raise ValueError('Expected a complete Google Cloud KMS crypto key resource')
    return key


def kms(action, value, config, context):
    if action not in ('encrypt', 'decrypt'):
        raise ValueError('Unsupported KMS operation')
    key = validate_key(config['kms_key'])
    field = 'plaintext' if action == 'encrypt' else 'ciphertext'
    payload = {field: base64.b64encode(value).decode(),
               'additionalAuthenticatedData': base64.b64encode(context).decode()}
    response = json.loads(request('https://cloudkms.googleapis.com/v1/' + key + ':' + action,
                          {'Authorization': 'Bearer ' + access_token(config['service_account']),
                           'Content-Type': 'application/json'}, json.dumps(payload).encode()))
    return base64.b64decode(response['ciphertext' if action == 'encrypt' else 'plaintext'], validate=True)
