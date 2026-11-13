"""Interactive company DNS enrollment; secret values never enter installation config."""
import os
import re

from uncloud_support import MISSING, trust_name
from uncloud_certificates import CloudflareCredentialError, cloudflare_preflight
from uncloud_terminal import can_prompt, prompt_line, prompt_secret

# ACME contact email is not enrollment identity — Let's Encrypt accepts any mailbox
# and we deliberately avoid binding a real operator inbox into Trust leftovers.
_IDENTITY_KEYS = ('certificate_mode', 'dns_zone', 'zone_id', 'acme_directory', 'profile')


def enroll(company, trust, config, non_interactive=False, progress=None):
    interactive = can_prompt(non_interactive)
    settings_name = 'vault_certlocker_certificate_settings'
    previous = trust.get(trust_name(company, settings_name))
    previous = previous if isinstance(previous, dict) else {}

    def answer(key, prompt, default=None):
        value = config.get(key) or previous.get(key) or default
        if not value and interactive:
            value = prompt_line(prompt.rstrip(': '), progress=progress)
        if not value:
            raise ValueError('Supply ' + key + ' in the non-secret setup config for unattended enrollment')
        return value

    mode = answer('certificate_mode', 'Certificate provider [customer/managed]')
    if mode not in ('customer', 'managed'):
        raise ValueError('certificate_mode must be customer or managed')
    if previous and previous.get('certificate_mode') != mode:
        raise ValueError(_mismatch_message(
            company, previous, {'certificate_mode': mode},
            reason='certificate_mode changed',
        ))
    if mode == 'managed':
        # Our provider credential stays in our Trust; never request or copy it here.
        settings = {'certificate_mode': mode}
    else:
        supplied_token = os.environ.pop('CLOUDFLARE_API_TOKEN', '').strip()
        zone = answer('dns_zone', 'Cloudflare DNS zone (for example example.com)')
        email = _acme_email(company, config, previous, interactive, progress)
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}', zone):
            raise ValueError('A valid DNS zone is required')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            raise ValueError('A valid ACME registration email is required')
        variable = 'vault_cloudflare_ini_key'
        if previous.get('dns_zone') and previous['dns_zone'] != zone:
            raise ValueError(_mismatch_message(company, previous, dict(previous, dns_zone=zone)))
        existing = trust.get(trust_name(company, variable))
        candidate = supplied_token if existing is MISSING or existing == '' else None
        while True:
            # A saved, valid credential is reused. An environment value only replaces
            # a saved credential after Cloudflare has rejected the saved one.
            if existing is not MISSING and existing != '' and candidate is None:
                try:
                    _, zone_id = cloudflare_preflight(company, trust, zone)
                    break
                except CloudflareCredentialError as error:
                    if not interactive and not supplied_token:
                        raise CloudflareCredentialError(str(error) +
                            '. Correct the record in Trust or supply CLOUDFLARE_API_TOKEN to replace the rejected credential') from None
                    print(str(error), flush=True)
                    candidate = supplied_token
            if not candidate:
                if not interactive:
                    raise ValueError('Company Cloudflare token missing; set CLOUDFLARE_API_TOKEN for unattended setup, '
                                     'or rerun in a terminal for hidden input')
                candidate = prompt_secret(
                    'Cloudflare User API token (hidden; replaces a rejected token in company Trust)',
                    env_name='CLOUDFLARE_API_TOKEN', progress=progress)
            class Candidate:
                def get(self, name):
                    return candidate
            try:
                cloudflare_preflight(company, Candidate(), zone)
            except CloudflareCredentialError as error:
                if not interactive:
                    raise
                print(str(error), flush=True)
                candidate = supplied_token = ''
                continue
            if existing is MISSING or existing == '':
                trust.populate_empty(company, variable, candidate)
            else:
                replace_rejected_cloudflare_token(company, trust, existing, candidate)
            # Validate the stored value too, including a concurrent enrollment.
            _, zone_id = cloudflare_preflight(company, trust, zone)
            break
        settings = {'certificate_mode': mode, 'dns_zone': zone, 'acme_email': email, 'zone_id': zone_id}
    settings.update(acme_directory='https://acme-v02.api.letsencrypt.org/directory', profile='shortlived')
    if previous and _identity(previous) != _identity(settings):
        raise ValueError(_mismatch_message(company, previous, settings))
    if previous:
        # Keep the Trust record as enrolled; contact email changes are ignored.
        settings = dict(previous)
    saved = trust.ensure(company, settings_name, lambda: settings)
    if _identity(saved) != _identity(settings):
        raise ValueError('Concurrent certificate enrollment differs from the requested settings')
    print('Certificate enrollment saved in the company Trust group; provider credentials stay out of local config.', flush=True)
    return settings


def replace_rejected_cloudflare_token(company, trust, previous, candidate):
    """Replace only the rejected company record, after validating its replacement."""
    import json
    from urllib.parse import quote
    variable = 'vault_cloudflare_ini_key'
    name = trust_name(company, variable)
    metadata = trust.request('api/v1/secret/lookup?name=' + quote(name, safe=''))
    if (not isinstance(metadata, dict) or metadata.get('name') != name or not metadata.get('id')
            or (trust.group and metadata.get('groups') != [trust.group])):
        raise ValueError('Cannot identify the rejected company Cloudflare record safely')
    identifier = quote(str(metadata['id']), safe='')
    if json.loads(trust.request('api/v1/secret/fetch/' + identifier, plain=True)) != {'value': previous}:
        raise ValueError('Cloudflare credential changed concurrently; retry enrollment')
    try:
        trust.request('api/v1/secret/revoke/' + identifier, {})
    except RuntimeError:
        if trust.get(name) is not MISSING:
            raise
    if trust.get(name) is not MISSING:
        raise RuntimeError('Rejected Cloudflare credential revocation not confirmed')
    saved = trust.ensure(company, variable, lambda: candidate)
    if saved != candidate:
        raise ValueError('Cloudflare credential changed concurrently; retry enrollment')


def disposable_acme_email(company):
    """Non-personal ACME contact so a real inbox is not registered with the CA."""
    return f'acme-{company}@certlocker.io'


def _acme_email(company, config, previous, interactive, progress):
    # Prefer this run's config, then a disposable default — not a leftover Trust
    # or operator mailbox that may already be registered with Let's Encrypt.
    value = (config.get('acme_email') or '').strip()
    if not value and interactive:
        value = prompt_line(
            'ACME registration email (any mailbox; disposable default avoids reusing a real inbox)',
            default=disposable_acme_email(company),
            progress=progress,
        )
    if not value:
        value = (previous.get('acme_email') or '').strip() or disposable_acme_email(company)
    return value


def _identity(settings):
    return {key: settings.get(key) for key in _IDENTITY_KEYS}


def _mismatch_message(company, previous, requested, reason=None):
    """Explain a Trust enrollment clash without printing secrets."""
    # Only compare identity keys so contact-email noise never surfaces here.
    keys = ('certificate_mode',) if reason else _IDENTITY_KEYS
    diffs = []
    for key in keys:
        old, new = previous.get(key), requested.get(key)
        if old != new:
            diffs.append(f'{key}: saved={old!r} requested={new!r}')
    detail = '; '.join(diffs) if diffs else 'saved enrollment does not match this run'
    why = (reason + '. ' if reason else '') + detail
    return (
        f'Certificate settings for company {company!r} already exist in Trust and differ from this run ({why}). '
        'Reuse the enrolled certificate mode and DNS zone. Contact CertLocker before resetting an existing enrollment.'
    )
