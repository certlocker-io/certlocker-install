"""Check external setup dependencies before provisioning Ubuntu servers."""
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit, urlencode

from uncloud_support import bundled_release_manifest, validate_release_manifest, write_private, inventory_directory
from uncloud_enrollment import enroll
from uncloud_smtp import enroll_smtp
from uncloud_certificates import cloudflare_preflight, acme_profile_preflight
from uncloud_cloudflare import Cloudflare, check_access


def check_dns_ownership(api, zone_id, company, zone, names):
    legacy_comments = {'CertLocker '+company+' '+node for node in (company+'-a',company+'-b')}
    for field, hostname in names.items():
        rows=api.request('GET','zones/'+zone_id+'/dns_records?'+urlencode({'name':hostname,'per_page':100}))
        if not isinstance(rows,list) or len(rows)>=100:
            raise ValueError('DNS ownership lookup is incomplete')
        for row in rows:
            comment=row.get('comment','') or ''
            owned=(comment.startswith('CertLocker setup-ha '+company+' Grafana ')
                   if field=='grafana_hostname' else comment in legacy_comments)
            if row.get('type')!='A' or not owned:
                raise ValueError('Selected DNS hostname already has records outside this company installation: '+hostname)
    owner='CertLocker setup-ha '+company+' '+zone+' '
    for row in api.listing('zones/'+zone_id+'/load_balancers'):
        if row.get('name') in names.values() and row.get('description') != owner+row['name']:
            raise ValueError('Selected hostname belongs to another Cloudflare load balancer: '+row['name'])


def check_dependencies(company, trust, config, state_dir, interactive=False, progress=None):
    def note(message):
        if progress is not None:
            progress.detail(message)

    if any(key in config for key in ('smtp_password','smtp_pass','cloudflare_api_token','cloudflare_token','CLOUDFLARE_API_TOKEN','CERTLOCKER_TOKEN','TRUST_TOKEN','google_chat_webhook','google_chat_webhook_url','noc_google_chat_webhook','CERTLOCKER_GOOGLE_CHAT_WEBHOOK_URL')):
        raise ValueError('Company environment files must not contain passwords or API tokens; use hidden input or environment credentials')
    note('Validating front-office, backoffice and Grafana hostnames')
    zone = config.get('dns_zone')
    names = {}
    for key, field in (('front_url','hostname'),('backoffice_url','backoffice_hostname'),('grafana_url','grafana_hostname')):
        parsed = urlsplit(config.get(key,''))
        host = parsed.hostname or ''
        if (not zone or parsed.scheme!='https' or parsed.netloc!=host or parsed.path not in ('','/')
                or parsed.query or parsed.fragment or not host.endswith('.'+zone)
                or '.' in host[:-(len(zone)+1)]):
            raise ValueError('Supply three distinct HTTPS UI names one level below the configured DNS zone')
        names[field]=host
    if len(set(names.values()))!=3:
        raise ValueError('Front-office, backoffice and Grafana names must be distinct')
    note('Checking company ingress names in Trust')
    observed = trust.ensure(company,'vault_certlocker_ingress_settings',lambda:names)
    if observed != names:
        raise ValueError('The company Trust DNS names differ from this environment file; resume cannot replace another installation’s names')
    note('Enrolling certificate provider settings in Trust')
    settings = enroll(company, trust, config, non_interactive=not interactive, progress=progress)
    if settings.get('certificate_mode')!='customer':
        raise ValueError('This workflow currently requires customer certificate mode; managed certificate bootstrap is not commissioned')
    note('Checking Cloudflare DNS token and zone access')
    token, zone_id = cloudflare_preflight(company,trust,zone)
    api=Cloudflare(token)
    if config.get('cloudflare_load_balancing',True):
        note('Checking Cloudflare Load Balancing permissions')
        check_access(api,zone_id,zone)
        note('Checking DNS hostname ownership')
        check_dns_ownership(api,zone_id,company,zone,names)
    note('Checking ACME shortlived profile')
    acme_profile_preflight(settings['acme_directory'],settings['profile'])
    if config.get('reuse_issued_certificate'):
        from uncloud_certificates import validate_reuse_source
        note('Validating reusable issued certificate in Trust')
        validate_reuse_source(company, trust)
    trust.ensure(company,'vault_certlocker_application_settings',lambda:{
        'public_url':'https://'+names['hostname'],'smtp_host':'','smtp_user':'',
        'smtp_enabled':False,'ghcr_username':'sean-certlocker'})
    note('Checking application mail TLS and authentication')
    mail = enroll_smtp(company, trust, config, non_interactive=not interactive, progress=progress)
    if not mail['smtp_enabled']:
        raise ValueError('Application mail is required before provisioning')
    from uncloud_install_notification import preflight as chat_preflight
    note('Checking the installation notification destination in Trust')
    chat_status = chat_preflight(config)
    # Pin a verified release once; resuming must never silently advance to a newer release.
    note('Pinning or verifying the immutable application release')
    directory=Path(state_dir)
    manifest_path=directory/'bootstrap-release.json'
    checksum_path=manifest_path.with_suffix('.json.sha256')
    if manifest_path.exists() != checksum_path.exists():
        raise ValueError('Incomplete bootstrap release pin; restore its matching manifest/checksum before resume')
    if manifest_path.exists():
        raw=manifest_path.read_bytes()
        if checksum_path.read_text().strip() != hashlib.sha256(raw).hexdigest():
            raise ValueError('Bootstrap release checksum mismatch')
        manifest=validate_release_manifest(json.loads(raw))
    else:
        installed = inventory_directory(company)/'release.json'
        if installed.exists():
            manifest = validate_release_manifest(json.loads(installed.read_text()))
        else:
            manifest,_=bundled_release_manifest(config.get('release_manifest') or Path(__file__).resolve().parents[1]/'releases/current.json')
        raw=(json.dumps(manifest,sort_keys=True)+'\n').encode()
        write_private(manifest_path,raw.decode())
        write_private(checksum_path,hashlib.sha256(raw).hexdigest()+'\n')
    note('Dependency checks passed')
    return {'manifest_file':str(manifest_path),'release':manifest['release'],
            'certificate_and_cloudflare':'passed',
            'smtp':'TLS/authentication passed',
            'monitoring_webhook':'company-owned optional integration',
            'installation_notification':chat_status}
