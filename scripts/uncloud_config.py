"""Collect non-secret answers for a fresh company CertLocker HA environment."""
import ipaddress
import os
import json
import re
import subprocess
import sys
from urllib.parse import urlsplit

from uncloud_nodes import node_names
from uncloud_access import customer_cidrs

def google(*args):
    result = subprocess.run(['gcloud', *args, '--format=json', '--quiet'],
                            capture_output=True, text=True)
    if result.returncode and sys.stdin.isatty() and any(word in result.stderr.lower() for word in ('reauth', 'invalid_grant', 'credentials', 'auth login')):
        subprocess.run(['gcloud', 'auth', 'login', '--update-adc'], check=True)
        result = subprocess.run(['gcloud', *args, '--format=json', '--quiet'],
                                capture_output=True, text=True)
    if result.returncode:
        raise ValueError('Google access failed. Run gcloud auth login --update-adc and retry.')
    return json.loads(result.stdout)

def ask(prompt, default=None, validate=None):
    while True:
        value = input(prompt + (f' [{default}]' if default is not None else '') + ': ').strip()
        value = value or default
        try:
            if value is None or (value == '' and default != ''):
                raise ValueError('A value is required')
            return validate(value) if validate else value
        except (ValueError, TypeError) as error:
            print(str(error), flush=True)

def choose(prompt, options, default=None, allow_custom=False):
    """Accept a displayed number or exact value, without guessing a selection."""
    if not options:
        raise ValueError('No choices are available for ' + prompt)
    for number, (value, label) in enumerate(options, 1):
        print(f'  {number}. {label} ({value})', flush=True)
    values = [value for value, _ in options]
    shown_default = str(values.index(default)+1) if default in values else default
    def selection(value):
        if value.isdecimal():
            index = int(value)-1
            if not 0 <= index < len(values):
                raise ValueError('Choose a number from the list')
            return values[index]
        if value in values or allow_custom:
            return value
        raise ValueError('Choose a number or an exact value from the list')
    return ask(prompt, shown_default, selection)


def choose_google_project():
    print('Sign in to Google Cloud and choose the account for this installation.', flush=True)
    login_env = dict(os.environ)
    login_env.pop('CLOUDSDK_CORE_DISABLE_PROMPTS', None)
    if os.environ.get('CERTLOCKER_GOOGLE_LOGIN_DONE') != '1':
        result = subprocess.run(['gcloud', 'auth', 'login', '--update-adc'], env=login_env)
        if result.returncode:
            raise ValueError('Google login did not complete; no project was selected')
    else:
        print('Using Google sign-in completed by the workstation launcher.',flush=True)
    projects = google('projects', 'list', '--filter=lifecycleState:ACTIVE')
    projects = sorted(projects, key=lambda row: row['projectId'])
    options = [(row['projectId'], row.get('name') or row['projectId']) for row in projects]
    if not options:
        raise ValueError('The signed-in Google account has no accessible active projects')
    print('Projects available to your Google account:', flush=True)
    return choose('Select Google project (number or project ID)', options,
                  options[0][0] if len(options)==1 else None)

def email(value):
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        raise ValueError('Enter a valid email address')
    return value.lower()

def collect(company, machine_type=None, boot_disk_size_gb=None):
    # Deliberately start with product defaults, never a previous customer's answers.
    def group(value):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}',value):
            raise ValueError('Enter the exact Trust group name, up to 64 characters')
        return value
    trust_group = ask('Exact company Trust group', company, group)
    selected = choose_google_project()
    zones = {row['name'] for row in google('compute', 'zones', 'list', '--project', selected)
             if row.get('status') == 'UP'}
    if len(zones)<2:
        raise ValueError('This project needs at least two available Google zones')
    print('Examples: europe-west1-b: Belgium; europe-west4-a: Netherlands; us-central1-a: Iowa, USA.')
    print('The final letter selects a zone within a region. Locations: https://docs.cloud.google.com/compute/docs/regions-zones')
    nodes = {}
    chosen = []
    for index, node in enumerate(node_names(company)):
        defaults = ('europe-west1-b','europe-west4-a')
        available_zones = sorted(zones-set(chosen))
        default_zone = defaults[index] if defaults[index] in available_zones else available_zones[0]
        location = choose(f'Server {index+1} zone (number or zone name)',
                          [(value, value.rsplit('-',1)[0]) for value in available_zones], default_zone)
        chosen.append(location)
        def machine(value):
            details = google('compute', 'machine-types', 'describe', value, '--project', selected, '--zone', location)
            if details.get('guestCpus',0)<2 or details.get('memoryMb',0)<8192:
                raise ValueError('Choose at least 2 vCPUs and 8 GiB RAM')
            return value
        while True:
            size = choose(f'Server {index+1} VM type (number, listed type or another machine type)',
                [('e2-standard-2','2 vCPUs / 8 GiB'),('e2-standard-4','4 vCPUs / 16 GiB'),
                 ('e2-standard-8','8 vCPUs / 32 GiB')], machine_type or 'e2-standard-2', allow_custom=True)
            try:
                size = machine(size)
                break
            except ValueError as error:
                print(str(error), flush=True)
        nodes[node] = {'zone': location, 'machine_type': size}
    def disk(value):
        value = int(value)
        if not 50 <= value <= 1000:
            raise ValueError('Choose 50–1000 GiB')
        return value
    disk_size = ask('Boot disk size per server in GiB', str(boot_disk_size_gb or 100), disk)
    def domain(value):
        if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}',value):
            raise ValueError('Enter a DNS domain such as example.com')
        return value
    dns_zone = ask('Cloudflare DNS zone', 'certlocker.io', domain)
    def url(value):
        parsed=urlsplit(value)
        if parsed.scheme!='https' or parsed.netloc!=parsed.hostname or parsed.path not in ('','/') or parsed.query or parsed.fragment:
            raise ValueError('Enter an HTTPS URL without a path')
        host=domain(parsed.hostname or '')
        if not host.endswith('.'+dns_zone) or host.count('.') != dns_zone.count('.')+1:
            raise ValueError('URL must be one subdomain below the DNS zone for its wildcard certificate')
        return 'https://'+host
    deployment=choose('Deployment type',
                      [('dev','Development / non-production'),
                       ('prod','Production')], 'dev')
    front=ask('Front-office URL', 'https://'+company+'.'+dns_zone, url)
    back=ask('Backoffice URL', 'https://backoffice-'+company+'.'+dns_zone, url)
    grafana='https://grafana-cl-'+company+'.'+dns_zone
    if len({front,back,grafana}) != 3:
        raise ValueError('All three URLs must be distinct')
    admin=ask('Company superuser email', validate=email)
    account_domain=ask('Company account email domain', admin.split('@')[1], domain)
    display=ask('Superuser display name', admin.split('@')[0])
    # Any mailbox works for ACME; avoid defaulting to the operator inbox so a
    # real address is not registered with Let's Encrypt from lab installs.
    acme=ask('ACME registration email (any mailbox)', f'acme-{company}@certlocker.io', email)
    vpn_cidrs = ask('Additional customer VPN / whitelist IPv4 addresses, comma-separated', '', customer_cidrs)
    def port(value):
        value=int(value)
        if not 1 <= value <= 65535:
            raise ValueError('Choose an SMTP port from 1 to 65535')
        return value
    from uncloud_smtp import advise_customer_smtp, advise_mail_ownership
    from uncloud_terminal import prompt_secret
    advise_mail_ownership()
    mode=choose('Application mail', [
        ('customer', 'Your Gmail/SMTP mailbox (asks for username + App Password now)'),
        ('managed', 'CertLocker mail already provisioned in this company Trust group'),
    ])
    config={'company': company, 'trust_group':trust_group, 'deployment':deployment,
            'google_project':selected, 'ssh_user':'ucdeploy',
            'ssh_private_key':'~/.ssh/certlocker-'+company, 'nodes':nodes,
            'boot_disk_size_gb':disk_size, 'vpn_cidrs':vpn_cidrs,
            'registry_mode':'ghcr','runtime_backend':'host',
            'certificate_mode':'customer','dns_zone':dns_zone,'acme_email':acme,
            'front_url':front,'backoffice_url':back,'grafana_url':grafana,
            'initial_admin_email':admin,'account_domain':account_domain,'admin_display_name':display,
            'smtp_mode':mode, 'cloudflare_load_balancing':True,'cloudflare_monitor_interval':60}
    if mode=='customer':
        print('Collecting your application mail account now (Gmail App Password or provider SMTP password).', flush=True)
        advise_customer_smtp()
        config.update(smtp_host=ask('SMTP host', 'smtp.gmail.com'),
                      smtp_user=ask('Gmail / SMTP username (full address)'),
                      smtp_tls=choose('SMTP encryption', [('starttls','STARTTLS, usually port 587'),('tls','Implicit TLS, usually port 465')], 'starttls'))
        config['smtp_port']=ask('SMTP port', '465' if config['smtp_tls']=='tls' else '587', port)
        # Password stays out of the company JSON; setup-ha enroll reads this env once.
        os.environ['CERTLOCKER_SMTP_PASSWORD'] = prompt_secret(
            'Gmail/SMTP App Password (hidden; verified and stored in company Trust during setup)',
            env_name='CERTLOCKER_SMTP_PASSWORD',
        )
    from uncloud_support import ensure_certlocker_token
    # Fresh wizard always asks; do not reuse a stale shell CERTLOCKER_TOKEN.
    ensure_certlocker_token(interactive=True)
    print('Cloudflare API token is collected with hidden input during setup and stored in Trust.', flush=True)
    from certlocker_gateway import GatewayRoutes
    config['trust_account_id'] = GatewayRoutes().account_id
    return config
