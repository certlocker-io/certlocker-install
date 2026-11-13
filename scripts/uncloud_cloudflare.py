"""Company-owned Cloudflare health routing; never manages subscriptions or other sites."""
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from uncloud_support import NoRedirect, company_slug


class CloudflareHTTPError(RuntimeError):
    def __init__(self, status, operation, detail=''):
        self.status = status
        self.detail = detail
        suffix = (': ' + detail) if detail else '; private response suppressed'
        super().__init__(f'Cloudflare {operation} returned HTTP {status}{suffix}')


def operation_name(path):
    parts = path.split('?', 1)[0].split('/')
    if 'load_balancers' in parts:
        if 'pools' in parts:
            return 'account Load Balancing pools API'
        if 'monitors' in parts:
            return 'account Load Balancing monitors API'
        return 'zone Load Balancers API'
    return 'zone details API'


def _safe_api_detail(payload):
    """Keep only Cloudflare error codes/messages; never echo request or secret material."""
    if not isinstance(payload, dict):
        return ''
    parts = []
    for error in payload.get('errors') or []:
        if not isinstance(error, dict):
            continue
        code = error.get('code')
        message = error.get('message')
        if isinstance(message, str):
            message = re.sub(r'(?i)(key|token|secret|authorization|bearer)=[^&\s]+', r'\1=[REDACTED]', message)
            message = message.strip()[:200]
        if code is not None and message:
            parts.append(f'{code}: {message}')
        elif message:
            parts.append(message)
        elif code is not None:
            parts.append(str(code))
        for child in error.get('error_chain') or []:
            if isinstance(child, dict) and isinstance(child.get('message'), str):
                chained = child['message'].strip()[:200]
                if chained:
                    parts.append(chained)
    return '; '.join(parts[:5])


class Cloudflare:
    def __init__(self, token):
        self.token = token

    def request(self, method, path, body=None):
        request = urllib.request.Request('https://api.cloudflare.com/client/v4/' + path,
            method=method, data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            detail = ''
            try:
                detail = _safe_api_detail(json.loads(error.read().decode('utf-8', 'replace')))
            except (OSError, ValueError, json.JSONDecodeError):
                detail = ''
            raise CloudflareHTTPError(error.code, operation_name(path), detail) from None
        except (OSError, ValueError):
            raise RuntimeError('Cloudflare health-routing response unavailable; reconcile before retrying') from None
        if result.get('success') is not True:
            detail = _safe_api_detail(result)
            raise RuntimeError(
                'Cloudflare health-routing operation failed'
                + ((': ' + detail) if detail else '; private response suppressed')
            )
        return result['result']

    def listing(self, path):
        # Never infer absence from an incomplete collection.
        entries = []
        for page in range(1, 101):
            rows = self.request('GET', path + f'?per_page=100&page={page}')
            if not isinstance(rows, list):
                raise ValueError('Cloudflare collection is malformed')
            entries.extend(rows)
            if len(rows) < 100:
                return entries
        raise ValueError('Cloudflare collection exceeds the bounded discovery limit')


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-fA-F0-9]{32}', value):
        raise ValueError('Invalid Cloudflare resource identifier')
    return value


def check_access(api, zone_id, zone_name):
    zone = api.request('GET', 'zones/' + identifier(zone_id))
    if zone.get('name') != zone_name:
        raise ValueError('Cloudflare zone identity mismatch')
    account = identifier(zone['account']['id'])
    checks = (
        ('zones/' + zone_id + '/load_balancers', 'Zone > Load Balancers > Edit on the selected zone'),
        ('accounts/' + account + '/load_balancers/pools', 'Account > Load Balancing: Monitors and Pools > Edit on the zone owner account'),
        ('accounts/' + account + '/load_balancers/monitors', 'Account > Load Balancing: Monitors and Pools > Edit on the zone owner account'))
    for path, permission in checks:
        try:
            api.listing(path)
        except CloudflareHTTPError as error:
            if error.status == 403:
                raise RuntimeError(str(error) + '. Check token permission: ' + permission +
                    '. Also check token resource scope, IP restrictions and the account Load Balancing subscription.') from None
            raise
    return account


def plan(company, zone, names, addresses, interval=60):
    company_slug(company)
    hostname = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
    if not hostname.fullmatch(zone) or len(names) != 2 or len(set(names)) != 2:
        raise ValueError('One DNS zone and two distinct UI hostnames are required')
    if any(not hostname.fullmatch(name) or not name.endswith('.' + zone) for name in names):
        raise ValueError('Both UI names must be explicit hostnames inside the selected zone')
    if len(addresses) != 2 or not all(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', name) for name in addresses) or len(set(addresses.values())) != 2:
        raise ValueError('Exactly two distinct installed HA origins are required')
    if any(not ipaddress.IPv4Address(address).is_global for address in addresses.values()):
        raise ValueError('Cloudflare origins must be public IPv4 addresses')
    if type(interval) is not int or interval < 10 or interval > 300:
        raise ValueError('Monitor interval must be 10..300 seconds and supported by the account')
    owner = 'CertLocker setup-ha ' + company + ' ' + zone
    suffix = hashlib.sha256(json.dumps([company, zone, sorted(names)]).encode()).hexdigest()[:16]
    return {'company': company, 'zone': zone, 'names': names, 'addresses': addresses,
        'monitor': {'description': owner + ' readiness', 'type': 'https', 'method': 'GET',
            'path': '/health/ready', 'header': {'Host': [names[0]]},
            'timeout': 3, 'retries': 0, 'interval': interval, 'expected_codes': '200',
            'expected_body': 'ready', 'allow_insecure': False, 'follow_redirects': False,
            'consecutive_up': 1, 'consecutive_down': 1},
        'pool': {'name': 'certlocker-' + suffix, 'description': owner + ' origins',
            'enabled': True, 'minimum_origins': 1,
            'origins': [{'name': node, 'address': address, 'enabled': True, 'weight': 1}
                        for node, address in sorted(addresses.items())]},
        'load_balancers': [{'name': name, 'description': owner + ' ' + name,
            'enabled': True, 'proxied': True, 'session_affinity': 'cookie',
            'session_affinity_ttl': 86400,
            'session_affinity_attributes': {'secure': 'Always', 'samesite': 'Lax',
                                            'zero_downtime_failover': 'sticky'},
            'steering_policy': 'off'} for name in names]}


def matches(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and matches(actual[key], value)
                                               for key, value in desired.items())
    if isinstance(desired, list):
        return isinstance(actual, list) and len(actual) == len(desired) and all(
            any(matches(item, expected) for item in actual) for expected in desired)
    return actual == desired


def owned(entries, desired, key):
    found = [row for row in entries if row.get(key) == desired[key]]
    if len(found) > 1 or any(row.get('description') != desired['description'] for row in found):
        raise ValueError('Existing Cloudflare resource is ambiguous or not owned by this installation')
    return found[0] if found else None


def reconcile(api, path, desired, key):
    existing = owned(api.listing(path), desired, key)
    if existing and matches(existing, desired):
        return identifier(existing['id'])
    try:
        suffix = '/' + identifier(existing['id']) if existing else ''
        api.request('PATCH' if existing else 'POST', path + suffix, desired)
    except RuntimeError:
        # Includes lost write responses. Read back exactly once; never replay POST.
        found = owned(api.listing(path), desired, key)
        if not found or not matches(found, desired):
            raise
    found = owned(api.listing(path), desired, key)
    if not found or not matches(found, desired):
        raise RuntimeError('Cloudflare resource read-back differs from requested configuration')
    return identifier(found['id'])


def verify_origins(settings):
    context = ssl.create_default_context()
    for address in settings['addresses'].values():
        for name in settings['names']:
            with socket.create_connection((address, 443), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=name) as connection:
                    connection.sendall(('GET /health/ready HTTP/1.0\r\nHost: ' + name +
                        '\r\nUser-Agent: Mozilla/5.0 CertLocker-HA\r\n\r\n').encode())
                    response = b''
                    while len(response) < 65536:
                        data = connection.recv(8192)
                        if not data:
                            break
                        response += data
                    head, _, body = response.partition(b'\r\n\r\n')
                    if not re.match(rb'HTTP/1\.[01] 200(?: |\r)', head) or body.strip() != b'ready':
                        raise RuntimeError('Every origin must pass hostname-verified HTTPS readiness before routing changes')


def pool_observations(value, addresses):
    observations = {address: [] for address in addresses}
    def visit(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key in observations and isinstance(child, dict):
                    observations[key].append(child.get('healthy') is True and child.get('response_code') == 200)
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value.get('pop_health', {}))
    return observations


def pool_healthy(value, addresses, *, min_pop_ratio=0.95):
    """Both origins must be observed and healthy from nearly all publishing PoPs.

    Cloudflare publishes one result per PoP. A few distant edges can time out without
    the origin being down, so require coverage on every configured address and at
    least ``min_pop_ratio`` healthy PoP checks per origin (default 95%).
    """
    observations = pool_observations(value, addresses)
    if not all(observations.values()):
        return False
    return all(sum(values) / len(values) >= min_pop_ratio for values in observations.values())


def wait_pool_health(api, path, desired_pool, addresses, interval):
    """Wait for scheduled observations on both creation and read-only verification."""
    deadline = time.monotonic() + interval * 3 + 30
    summary = 'No published health observations'
    print('Waiting for Cloudflare to verify both HTTPS origins', flush=True)
    while True:
        try:
            health = api.request('GET', path + '/health')
        except CloudflareHTTPError as error:
            if error.status != 404:
                raise
            # Only tolerate missing observations while the exact owned pool exists.
            if not matches(api.request('GET', path), desired_pool):
                raise RuntimeError('Cloudflare pool changed while waiting for health checks') from None
        else:
            if pool_healthy(health, addresses):
                return
            observations = pool_observations(health, addresses)
            checks = [ok for values in observations.values() for ok in values]
            per_origin = ', '.join(
                f'{address} {sum(values)}/{len(values)}'
                for address, values in observations.items() if values
            )
            summary = (
                f'{sum(checks)}/{len(checks)} published checks passed across '
                f'{len(observations)} configured origins'
            )
            if per_origin:
                summary += f' ({per_origin})'
        if time.monotonic() >= deadline:
            raise RuntimeError('Cloudflare has not verified both origins within the health observation deadline: ' + summary)
        time.sleep(5)


def _company_owned_pools(pools, description, exclude_name=None):
    """Pools marked for this installation; hostname changes only alter the hashed name."""
    return [row for row in pools
            if row.get('description') == description and row.get('name') != exclude_name]


def purge_stale_company_pools(api, paths, settings):
    """Delete older hashed pools for this company/zone before creating the current one.

    Pool names include a hash of the UI hostnames. A rebuild with different names
    leaves the previous pool holding the same origin IPs; Cloudflare then rejects
    the new pool create with HTTP 400.
    """
    description = settings['pool']['description']
    desired_name = settings['pool']['name']
    owner_prefix = description[:-len(' origins')] if description.endswith(' origins') else description
    pools = api.listing(paths['pool'])
    lbs = api.listing(paths['lb'])
    stale = _company_owned_pools(pools, description, exclude_name=desired_name)
    removed = []
    for pool in stale:
        pool_id = identifier(pool['id'])
        referencing = [
            lb for lb in lbs
            if pool_id in (lb.get('default_pools') or []) or lb.get('fallback_pool') == pool_id
        ]
        for lb in referencing:
            desc = lb.get('description') or ''
            if not desc.startswith(owner_prefix + ' '):
                raise ValueError(
                    'Stale company Cloudflare pool is referenced by an unowned load balancer; refusing cleanup'
                )
            api.request('DELETE', paths['lb'] + '/' + identifier(lb['id']))
            if any(row.get('id') == lb.get('id') for row in api.listing(paths['lb'])):
                raise RuntimeError('Could not remove load balancer attached to stale company pool')
        api.request('DELETE', paths['pool'] + '/' + pool_id)
        if any(row.get('id') == pool.get('id') for row in api.listing(paths['pool'])):
            raise RuntimeError('Could not remove stale company Cloudflare pool')
        print('Removed stale Cloudflare pool from a previous hostname set: ' + str(pool.get('name')), flush=True)
        removed.append(pool.get('name'))
    return removed


def apply(api, zone_id, account_id, settings):
    prefix = 'accounts/' + identifier(account_id) + '/load_balancers/'
    paths = {'monitor': prefix + 'monitors', 'pool': prefix + 'pools',
             'lb': 'zones/' + identifier(zone_id) + '/load_balancers'}
    # Drop older hashed pools for this company before conflict checks / create.
    stale_removed = purge_stale_company_pools(api, paths, settings)
    # Check read access and every naming conflict before making any change.
    snapshots = {kind: api.listing(path) for kind, path in paths.items()}
    owned(snapshots['monitor'], settings['monitor'], 'description')
    owned(snapshots['pool'], settings['pool'], 'name')
    for lb in settings['load_balancers']:
        owned(snapshots['lb'], lb, 'name')
    verify_origins(settings)
    monitor_id = reconcile(api, paths['monitor'], settings['monitor'], 'description')
    pool = dict(settings['pool'], monitor=monitor_id)
    pool_id = reconcile(api, paths['pool'], pool, 'name')
    wait_pool_health(api, paths['pool'] + '/' + pool_id, pool,
                     settings['addresses'].values(), settings['monitor']['interval'])
    lb_ids = [reconcile(api, paths['lb'], dict(lb, default_pools=[pool_id], fallback_pool=pool_id), 'name')
              for lb in settings['load_balancers']]
    return {'monitor': monitor_id, 'pool': pool_id, 'load_balancers': lb_ids,
            'names': settings['names'], 'stale_pools_removed': stale_removed,
            'both_origins_cloudflare_health_verified': True}


def verify(api, zone_id, account_id, settings):
    prefix = 'accounts/' + identifier(account_id) + '/load_balancers/'
    monitor = owned(api.listing(prefix + 'monitors'), settings['monitor'], 'description')
    if not monitor or not matches(monitor, settings['monitor']):
        raise RuntimeError('Cloudflare monitor configuration differs from setup')
    desired_pool = dict(settings['pool'], monitor=identifier(monitor['id']))
    pool = owned(api.listing(prefix + 'pools'), desired_pool, 'name')
    if not pool or not matches(pool, desired_pool):
        raise RuntimeError('Cloudflare pool configuration differs from setup')
    pool_id = identifier(pool['id'])
    balances = api.listing('zones/' + identifier(zone_id) + '/load_balancers')
    for lb in settings['load_balancers']:
        desired = dict(lb, default_pools=[pool_id], fallback_pool=pool_id)
        actual = owned(balances, desired, 'name')
        if not actual or not matches(actual, desired):
            raise RuntimeError('Cloudflare hostname routing differs from setup')
    verify_origins(settings)
    wait_pool_health(api, prefix + 'pools/' + pool_id, desired_pool,
                     settings['addresses'].values(), settings['monitor']['interval'])
    return {'names': settings['names'], 'configuration_and_both_origins': 'passed'}


def _company_owned_load_balancers(entries, owner_prefix, named):
    """LBs for this company/zone: exact current hostnames plus any older owned names."""
    found = []
    seen = set()
    for lb in named:
        hit = owned(entries, lb, 'name')
        if hit and hit.get('id') not in seen:
            found.append(hit)
            seen.add(hit.get('id'))
    marker = owner_prefix + ' '
    for row in entries:
        desc = row.get('description') or ''
        if not desc.startswith(marker) or row.get('id') in seen:
            continue
        # Description shape: "CertLocker setup-ha COMPANY ZONE hostname"
        hostname = desc[len(marker):]
        if not hostname or ' ' in hostname:
            raise ValueError('Unexpected company Cloudflare load balancer description; refusing teardown')
        found.append(row)
        seen.add(row.get('id'))
    return found


def remove(api, zone_id, account_id, settings):
    """Delete only this installation's load balancers, pools and monitor.

    Hostname changes rename the pool hash. Destroy must remove every pool and LB
    marked for this company/zone so a later up can recreate routing.
    """
    prefix = 'accounts/' + identifier(account_id) + '/load_balancers/'
    paths = {'monitor': prefix + 'monitors', 'pool': prefix + 'pools',
             'lb': 'zones/' + identifier(zone_id) + '/load_balancers'}
    snapshots = {kind: api.listing(path) for kind, path in paths.items()}
    monitor = owned(snapshots['monitor'], settings['monitor'], 'description')
    pool = owned(snapshots['pool'], settings['pool'], 'name')
    # Hostname-hash renames leave same-description pools under older names.
    stale_pools = _company_owned_pools(
        snapshots['pool'], settings['pool']['description'],
        exclude_name=(pool or {}).get('name'))
    company_pools = ([pool] if pool else []) + stale_pools
    owner_prefix = settings['pool']['description'][:-len(' origins')] if settings['pool']['description'].endswith(' origins') else settings['pool']['description']
    balances = _company_owned_load_balancers(snapshots['lb'], owner_prefix, settings['load_balancers'])
    if pool and settings['pool'].get('origins') and not matches(
            pool, {'description': settings['pool']['description'],
                   'origins': settings['pool']['origins']}):
        raise ValueError('Owned Cloudflare pool differs from this installation; refusing teardown')
    if any(row.get('description') != settings['pool']['description'] for row in company_pools):
        raise ValueError('Owned Cloudflare pool differs from this installation; refusing teardown')
    if balances and not company_pools:
        raise ValueError('Owned Cloudflare load balancer references an unavailable pool; refusing teardown')
    expected_monitor = identifier(monitor['id']) if monitor else None
    for candidate in company_pools:
        if candidate.get('monitor') not in (None, expected_monitor):
            raise ValueError('Owned Cloudflare pool references an unexpected monitor; refusing teardown')
    company_pool_ids = {identifier(item['id']) for item in company_pools}
    if company_pools:
        for item in balances:
            referenced = set(item.get('default_pools') or [])
            if item.get('fallback_pool'):
                referenced.add(item['fallback_pool'])
            if not referenced.issubset(company_pool_ids) or item.get('proxied') is not True:
                raise ValueError('Owned Cloudflare hostname points to an unexpected pool; refusing teardown')

    def delete(kind, item):
        if not item:
            return False
        resource_id = identifier(item['id'])
        try:
            api.request('DELETE', paths[kind] + '/' + resource_id)
        except RuntimeError:
            if any(row.get('id') == resource_id for row in api.listing(paths[kind])):
                raise
        if any(row.get('id') == resource_id for row in api.listing(paths[kind])):
            raise RuntimeError('Cloudflare teardown could not verify resource removal')
        return True

    # Remove hostname records before their referenced pool and monitor.
    deleted = sum(delete('lb', item) for item in balances)
    deleted += sum(delete('pool', item) for item in company_pools)
    deleted += int(delete('monitor', monitor))
    return {'load_balancers_removed': len(balances),
            'pool_removed': bool(company_pools),
            'monitor_removed': bool(monitor),
            'resources_removed': deleted,
            'stale_pools_removed': [item.get('name') for item in stale_pools]}


def remove_monitoring_dns(api, zone_id, company, hostname):
    """Remove only DNS records bearing this setup's explicit Grafana owner marker."""
    path = 'zones/' + identifier(zone_id) + '/dns_records'
    query = urllib.parse.urlencode({'name': hostname, 'per_page': 100, 'page': 1})
    rows = api.request('GET', path + '?' + query)
    if not isinstance(rows, list) or len(rows) >= 100:
        raise ValueError('Grafana DNS lookup is incomplete or exceeds its safe bound')
    marker = 'CertLocker setup-ha ' + company + ' Grafana '
    owned_rows = []
    for row in rows:
        if row.get('type') == 'A' and str(row.get('comment', '')).startswith(marker):
            if not re.fullmatch(re.escape(marker) + r'[a-z0-9-]+', row.get('comment', '')):
                raise ValueError('Unexpected setup-owned Grafana DNS record; refusing cleanup')
            owned_rows.append(row)
        else:
            raise ValueError('Grafana name contains unowned DNS records; refusing cleanup')
    for row in owned_rows:
        record_id = identifier(row.get('id'))
        api.request('DELETE', path + '/' + record_id)
        observed = api.request('GET', path + '?' + query)
        if any(item.get('id') == record_id for item in observed):
            raise RuntimeError('Grafana DNS cleanup could not confirm record removal')
    return {'hostname': hostname, 'records_removed': len(owned_rows)}


def remove_company_routing(api, zone_id, account_id, company, zone, names, addresses=None):
    """Recover partial setup by ownership, even before the final active marker exists.

    Destroy removes the current hashed pool and any older same-company pools left
    after hostname changes, plus owned LBs and the company monitor, so a later up
    can recreate Load Balancing without an origin-IP conflict.
    """
    company_slug(company)
    owner = 'CertLocker setup-ha ' + company + ' ' + zone
    suffix = hashlib.sha256(json.dumps([company, zone, sorted(names)]).encode()).hexdigest()[:16]
    settings = {
        'monitor': {'description': owner + ' readiness'},
        'pool': {'name': 'certlocker-' + suffix, 'description': owner + ' origins', 'origins': []},
        'load_balancers': [{'name': name, 'description': owner + ' ' + name} for name in names],
    }
    pools = api.listing('accounts/' + identifier(account_id) + '/load_balancers/pools')
    pool = owned(pools, settings['pool'], 'name')
    owned_by_description = _company_owned_pools(pools, settings['pool']['description'])
    if not pool:
        if len(owned_by_description) == 1:
            pool = owned_by_description[0]
        elif len(owned_by_description) > 1 and addresses is None:
            # Prefer recovering origins from a pool that still has two public origins.
            for candidate in owned_by_description:
                origins = candidate.get('origins', [])
                if len(origins) == 2:
                    pool = candidate
                    break
    if pool or owned_by_description:
        if addresses is None and pool:
            origins = pool.get('origins', [])
            if len(origins) != 2 or len({row.get('name') for row in origins}) != 2 or any(not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', row.get('name', '')) for row in origins):
                raise ValueError('Owned pool has unexpected origins; refusing teardown')
            addresses = {row['name']: row.get('address') for row in origins}
        if addresses is not None:
            # Reuse strict public-address and origin configuration validation.
            settings = plan(company, zone, names, addresses)
        elif owned_by_description and not pool:
            # No recoverable origins; still delete ownership-marked pools/LBs/monitor.
            pass
    result = remove(api, zone_id, account_id, settings)
    if result.get('stale_pools_removed'):
        print('Removed stale Cloudflare pools from earlier hostname sets: '
              + ', '.join(result['stale_pools_removed']), flush=True)
    return result
