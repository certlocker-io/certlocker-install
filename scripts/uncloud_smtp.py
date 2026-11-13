"""Company SMTP enrollment. Credentials stay in Trust, never installation config."""
import os
import re
import smtplib
import ssl

from uncloud_support import MISSING, replace_configuration, trust_name
from uncloud_terminal import can_prompt, prompt_line, prompt_secret

SETTINGS = 'vault_certlocker_application_settings'
PASSWORD = 'vault_certlocker_dataservice_smtp_pass'
MANAGED_SETTINGS = 'vault_certlocker_managed_smtp_settings'
MANAGED_PASSWORD = 'vault_certlocker_managed_smtp_pass'
SMTP_KEYS = {'smtp_host', 'smtp_user', 'smtp_enabled', 'smtp_port', 'smtp_tls', 'smtp_mode'}

CUSTOMER_SMTP_ADVICE = (
    'Application mail prerequisites (same as the HA guide mail chapter):\n'
    '  • Bring a mailbox username/sender and an SMTP or app password that allows TLS submission.\n'
    '  • Do not use a Cloudflare/API token unless that vendor documents SMTP authentication that way.\n'
    '  • Gmail: enable 2-Step Verification, create an App Password at '
    'https://myaccount.google.com/apppasswords, then use:\n'
    '      host smtp.gmail.com · username = full Gmail address · STARTTLS port 587 '
    '(or TLS port 465) · password = the 16-character App Password '
    '(not the Google account password).\n'
    '  • Other providers: their SMTP host, mailbox user, TLS/port, and SMTP/app password.\n'
    '  • Preflight authenticates only; it does not send email. '
    'Operator first-login Gmail does not provision application SMTP.\n'
    '  • Application mail is required. Prepare customer SMTP credentials or have '
    'CertLocker managed mail provisioned before continuing.'
)


def advise_customer_smtp():
    print(CUSTOMER_SMTP_ADVICE, flush=True)


def advise_mail_ownership():
    print(
        'Application mail is required. Choose application mail ownership:\n'
        '  yes      = your Gmail/SMTP mailbox (installer asks for full address + App Password)\n'
        '  no       = CertLocker managed mail already provisioned in this company Trust group\n'
        'See docs/INSTALLATION.md for the mail prerequisites.',
        flush=True,
    )
    advise_customer_smtp()


def validate(settings):
    if not isinstance(settings.get('smtp_enabled'), bool):
        raise ValueError('smtp_enabled must be a boolean')
    if not settings['smtp_enabled']:
        return
    host = settings.get('smtp_host', '')
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
        raise ValueError('A valid SMTP hostname is required')
    user = settings.get('smtp_user')
    if not isinstance(user, str) or not user.strip() or any(ord(c) < 32 for c in user):
        raise ValueError('An SMTP username is required')
    port = settings.get('smtp_port', 587)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('SMTP port must be an integer between 1 and 65535')
    if settings.get('smtp_tls', 'starttls') not in ('starttls', 'tls'):
        raise ValueError('SMTP TLS mode must be starttls or tls')


def managed_readiness(company, trust):
    settings = trust.get(trust_name(company, MANAGED_SETTINGS))
    password = trust.get(trust_name(company, MANAGED_PASSWORD))
    missing = []
    try:
        validate(dict(settings, smtp_enabled=True))
    except (ValueError, TypeError):
        missing.append(MANAGED_SETTINGS)
    if not isinstance(password, str) or not password:
        missing.append(MANAGED_PASSWORD)
    return settings, password, missing


def verify_smtp(settings, password):
    """Authenticate with the chosen SMTP account without sending a message."""
    if not settings['smtp_enabled']:
        return
    validate(settings)
    try:
        context = ssl.create_default_context()
        if settings.get('smtp_tls','starttls') == 'tls':
            connection = smtplib.SMTP_SSL(settings['smtp_host'],settings['smtp_port'],timeout=20,context=context)
        else:
            connection = smtplib.SMTP(settings['smtp_host'],settings['smtp_port'],timeout=20)
        with connection as client:
            client.ehlo()
            if settings.get('smtp_tls','starttls') == 'starttls':
                client.starttls(context=context)
                client.ehlo()
            client.login(settings['smtp_user'],password)
    except (OSError, smtplib.SMTPException, ValueError):
        raise ValueError('SMTP TLS/authentication check failed; no message was sent. Check the host, port, username and SMTP/app password in company Trust.') from None


def enroll_smtp(company, trust, config, non_interactive=False, progress=None):
    if any(key in config for key in ('smtp_password', 'smtp_pass')):
        raise ValueError('Do not put SMTP passwords in setup config; use hidden input or CERTLOCKER_SMTP_PASSWORD')
    previous = trust.get(trust_name(company, SETTINGS))
    if not isinstance(previous, dict):
        raise ValueError('Initialize company application settings before SMTP enrollment')
    interactive = can_prompt(non_interactive)
    mode = config.get('smtp_mode') or previous.get('smtp_mode')
    if not mode and interactive:
        advise_mail_ownership()
        choice = prompt_line('Use your own mail server? [yes/no]', progress=progress).lower()
        mode = {'yes': 'customer', 'y': 'customer', 'no': 'managed', 'n': 'managed'}.get(choice)
    if mode not in ('customer', 'managed'):
        raise ValueError('Application mail is required; choose smtp_mode customer or managed for setup')
    if previous.get('smtp_mode') and previous['smtp_mode'] != mode:
        raise ValueError('SMTP ownership differs from saved enrollment; update company Trust explicitly')
    if mode == 'managed' and not previous.get('smtp_mode'):
        while True:
            _, _, missing = managed_readiness(company, trust)
            if not missing:
                break
            detail = ', '.join(trust_name(company, name) for name in missing)
            if not interactive:
                raise ValueError('Managed application mail is not provisioned. Missing/invalid Trust records: ' + detail)
            print('Managed application mail is not ready. First-login email from the operator Gmail account does not provision application SMTP.',flush=True)
            print('Missing/invalid Trust records: '+detail,flush=True)
            print('Choose customer SMTP now, wait for managed mail, or stop.',flush=True)
            advise_customer_smtp()
            from uncloud_config import choose
            choice = choose('Application mail setup', [('customer','Configure customer SMTP (mailbox user + SMTP/app password)'),
                ('retry','Retry after the operator provisions managed mail'),
                ('stop','Stop and keep the current installation')], 'stop')
            if choice == 'stop':
                raise ValueError('Application mail setup stopped; provision the listed records or select an SMTP account on resume')
            if choice != 'retry':
                mode = choice
                config['smtp_mode'] = mode
                break
    settings = dict(previous, smtp_mode=mode, smtp_enabled=True)
    supplied_password = os.environ.pop('CERTLOCKER_SMTP_PASSWORD', '')
    if mode == 'customer':
        if interactive and not previous.get('smtp_mode'):
            print('Collecting your Gmail/SMTP account — full address and App Password from the checklist above.', flush=True)
            advise_customer_smtp()
        for key, prompt, default in (
                ('smtp_host', 'SMTP host', 'smtp.gmail.com'),
                ('smtp_user', 'Gmail / SMTP username (full address)', ''),
                ('smtp_tls', 'SMTP encryption (starttls/tls)', 'starttls'),
                ('smtp_port', 'SMTP port', None)):
            default = (465 if settings.get('smtp_tls') == 'tls' else 587) if key == 'smtp_port' else default
            value = config.get(key, previous.get(key) if previous.get('smtp_mode') else None)
            if value in (None, '') and interactive:
                value = prompt_line(prompt, default=default or None, progress=progress)
            elif value in (None, ''):
                value = default
            if key == 'smtp_port':
                if isinstance(value, bool):
                    raise ValueError('SMTP port must be an integer')
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    raise ValueError('SMTP port must be an integer') from None
            settings[key] = value
        if not settings.get('smtp_user'):
            raise ValueError('Gmail / SMTP username is required for customer application mail')
    elif mode == 'managed':
        # The delivery operator must provision this company's mail entitlement.
        # Customer setup never reads another group's shared mail credential.
        if not previous.get('smtp_mode'):
            provisioned = trust.get(trust_name(company, MANAGED_SETTINGS))
            if not isinstance(provisioned, dict) or not provisioned.get('smtp_host') or not provisioned.get('smtp_user'):
                raise ValueError('CertLocker mail must first be provisioned in this company Trust group')
            settings.update({key: value for key, value in provisioned.items()
                             if key in {'smtp_host', 'smtp_user', 'smtp_port', 'smtp_tls'}})
        settings.setdefault('smtp_port', 587)
        settings.setdefault('smtp_tls', 'starttls')
    validate(settings)
    if previous.get('smtp_mode') and settings != previous:
        raise ValueError('SMTP settings differ from saved enrollment; update company Trust explicitly')
    password_verified = False
    password = trust.get(trust_name(company, PASSWORD))
    if password is MISSING or password == '':
        if mode == 'managed':
            supplied_password = trust.get(trust_name(company, MANAGED_PASSWORD))
            if not isinstance(supplied_password, str) or not supplied_password:
                raise ValueError('CertLocker mail password is not provisioned in company Trust')
        if not supplied_password:
            if not interactive:
                raise ValueError('SMTP password missing; set CERTLOCKER_SMTP_PASSWORD for unattended setup, or rerun in a terminal')
            if progress is not None:
                progress.detail('Waiting for SMTP password on the terminal')
            supplied_password = prompt_secret(
                'Gmail/SMTP App Password (hidden; not the Google account password; saved in company Trust)',
                env_name='CERTLOCKER_SMTP_PASSWORD',
                progress=progress,
            )
        verify_smtp(settings, supplied_password)
        password_verified = True
        password = trust.populate_empty(company, PASSWORD, supplied_password)
    if not isinstance(password, str) or not password:
        raise ValueError('Company SMTP password is invalid')
    if not password_verified:
        verify_smtp(settings, password)
    config.update({key: settings[key] for key in SMTP_KEYS if key in settings})
    saved = replace_configuration(company, trust, SETTINGS, settings)
    print('SMTP selection saved in company Trust: ' + mode + '; password excluded from local config.', flush=True)
    return saved


def replace_smtp_password(company, trust, password):
    """Rotate the company DataService SMTP password (revoke + create)."""
    if not isinstance(password, str) or not password:
        raise ValueError('A non-empty SMTP password is required')
    name = trust_name(company, PASSWORD)
    existing = trust.get(name)
    if existing == password:
        return password
    if existing is not MISSING:
        trust.revoke_named(name)
        if trust.get(name) is not MISSING:
            raise RuntimeError('SMTP password revocation not confirmed; refusing to create a duplicate')
    return trust.ensure(company, PASSWORD, lambda: password)


def refresh_smtp(company, trust, config=None, non_interactive=False, progress=None):
    """Replace application mail settings and password after the environment is installed.

    Preserves public_url and ghcr_username. Intended for the supported mail configuration process /
    mail configuration so operators can change Gmail/SMTP without reinstalling.
    """
    config = dict(config or {})
    if any(key in config for key in ('smtp_password', 'smtp_pass')):
        raise ValueError('Do not put SMTP passwords in setup config; use hidden input or CERTLOCKER_SMTP_PASSWORD')
    previous = trust.get(trust_name(company, SETTINGS))
    if not isinstance(previous, dict):
        raise ValueError('Initialize company application settings before SMTP refresh')
    interactive = can_prompt(non_interactive)
    print('Refreshing application mail credentials in company Trust.', flush=True)
    advise_mail_ownership()
    mode = config.get('smtp_mode')
    if not mode and interactive:
        choice = prompt_line('Use your own mail server? [yes/no]', progress=progress).lower()
        mode = {'yes': 'customer', 'y': 'customer', 'no': 'managed', 'n': 'managed'}.get(choice)
    if mode not in ('customer', 'managed'):
        raise ValueError('Application mail is required; choose smtp_mode customer or managed for SMTP refresh')

    settings = dict(previous, smtp_mode=mode, smtp_enabled=True)
    supplied_password = os.environ.pop('CERTLOCKER_SMTP_PASSWORD', '')

    if mode == 'customer':
        advise_customer_smtp()
        print('Enter the Gmail/SMTP account to apply on the running installation.', flush=True)
        for key, prompt, default in (
                ('smtp_host', 'SMTP host', previous.get('smtp_host') or 'smtp.gmail.com'),
                ('smtp_user', 'Gmail / SMTP username (full address)', previous.get('smtp_user') or ''),
                ('smtp_tls', 'SMTP encryption (starttls/tls)', previous.get('smtp_tls') or 'starttls'),
                ('smtp_port', 'SMTP port', None)):
            default = (465 if settings.get('smtp_tls') == 'tls' else 587) if key == 'smtp_port' else default
            if key == 'smtp_port' and previous.get('smtp_port') not in (None, ''):
                default = previous.get('smtp_port')
            value = config.get(key)
            if value in (None, '') and interactive:
                value = prompt_line(prompt, default=default or None, progress=progress)
            elif value in (None, ''):
                value = default
            if key == 'smtp_port':
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    raise ValueError('SMTP port must be an integer') from None
            settings[key] = value
        if not settings.get('smtp_user'):
            raise ValueError('Gmail / SMTP username is required for customer application mail')
    elif mode == 'managed':
        provisioned = trust.get(trust_name(company, MANAGED_SETTINGS))
        if not isinstance(provisioned, dict) or not provisioned.get('smtp_host') or not provisioned.get('smtp_user'):
            raise ValueError('CertLocker mail must first be provisioned in this company Trust group')
        settings.update({key: value for key, value in provisioned.items()
                         if key in {'smtp_host', 'smtp_user', 'smtp_port', 'smtp_tls'}})
        settings.setdefault('smtp_port', 587)
        settings.setdefault('smtp_tls', 'starttls')
        supplied_password = trust.get(trust_name(company, MANAGED_PASSWORD))
        if not isinstance(supplied_password, str) or not supplied_password:
            raise ValueError('CertLocker mail password is not provisioned in company Trust')
    validate(settings)
    if not supplied_password:
        if not interactive:
            raise ValueError(
                'SMTP password missing; set CERTLOCKER_SMTP_PASSWORD for unattended refresh, or rerun in a terminal'
            )
        if progress is not None:
            progress.detail('Waiting for SMTP password on the terminal')
        supplied_password = prompt_secret(
            'Gmail/SMTP App Password (hidden; not the Google account password; saved in company Trust)',
            env_name='CERTLOCKER_SMTP_PASSWORD',
            progress=progress,
        )
    verify_smtp(settings, supplied_password)
    replace_smtp_password(company, trust, supplied_password)

    saved = replace_configuration(company, trust, SETTINGS, settings, allow_smtp_refresh=True)
    config.update({key: settings[key] for key in SMTP_KEYS if key in settings})
    print('SMTP refresh saved in company Trust: ' + mode + '; password excluded from local config.', flush=True)
    return saved
