"""Manage only the DNS records owned by the selected company installation."""
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from uncloud_certificates import cloudflare_preflight
from uncloud_support import NoRedirect
from uncloud_nodes import node_names

LAB_COMPANY = 'example'
LAB_NAMES = ('certlocker.example.com', 'backoffice.example.com')
LAB_NODES = node_names('certlocker')


class Records:
    def __init__(self, token, zone):
        self.token, self.zone = token, zone

    def request(self, method, suffix='', body=None):
        request = urllib.request.Request(
            'https://api.cloudflare.com/client/v4/zones/' + self.zone + '/dns_records' + suffix,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                value = json.load(response)
        except (OSError, ValueError):
            raise RuntimeError('Lab DNS operation failed; private response suppressed') from None
        if not isinstance(value, dict) or value.get('success') is not True:
            raise RuntimeError('Lab DNS operation was unsuccessful; private response suppressed')
        return value.get('result')

    def list(self, name):
        result = self.request('GET', '?name=' + urllib.parse.quote(name, safe='') + '&per_page=100')
        if not isinstance(result, list) or len(result) >= 100:
            raise ValueError('Unexpected or incomplete lab DNS record listing')
        return result


def preflight(records, nodes=None):
    nodes = nodes or LAB_NODES
    comments = {node: 'CertLocker ' + LAB_COMPANY + ' ' + node for node in nodes}
    # Check both names before changing either; existing unrelated records are never adopted.
    snapshots = {name: records.list(name) for name in LAB_NAMES}
    for name, entries in snapshots.items():
        if any(row.get('type') != 'A' or row.get('name') != name or row.get('comment') not in comments.values() for row in entries):
            raise ValueError('Assigned lab DNS name contains records not owned by this installer')
        if len({row['comment'] for row in entries}) != len(entries):
            raise ValueError('Duplicate installer-owned lab DNS records need reconciliation')
    return snapshots


def synchronize(records, addresses):
    nodes = node_names(LAB_COMPANY, addresses)
    if len(set(addresses.values())) != 2:
        raise ValueError('Exactly two distinct disposable-lab addresses are required')
    if any(not ipaddress.IPv4Address(value).is_global for value in addresses.values()):
        raise ValueError('Lab DNS requires public IPv4 addresses')
    comments = {node: 'CertLocker ' + LAB_COMPANY + ' ' + node for node in nodes}
    snapshots = preflight(records, nodes)
    changes = 0
    for name, entries in snapshots.items():
        for node in nodes:
            desired = {'type': 'A', 'name': name, 'content': addresses[node],
                       'proxied': True, 'ttl': 1, 'comment': comments[node]}
            existing = next((row for row in entries if row['comment'] == comments[node]), None)
            if existing and all(existing.get(key) == value for key, value in desired.items()):
                continue
            suffix = '/' + urllib.parse.quote(existing['id'], safe='') if existing else ''
            try:
                records.request('PATCH' if existing else 'POST', suffix, desired)
            except RuntimeError:
                # A lost write response is uncertain: read back, never blindly repeat it.
                found = [row for row in records.list(name) if row.get('comment') == comments[node]]
                if len(found) != 1 or not all(found[0].get(key) == value for key, value in desired.items()):
                    raise
            changes += 1
    for name in LAB_NAMES:
        entries = records.list(name)
        if len(entries) != 2 or any(row.get('type') != 'A' or row.get('name') != name or
                row.get('comment') not in comments.values() or row.get('proxied') is not True for row in entries):
            raise RuntimeError('Lab DNS read-back differs from the requested pair')
        for node in nodes:
            matches = [row for row in entries if row.get('comment') == comments[node]]
            if len(matches) != 1 or matches[0].get('content') != addresses[node]:
                raise RuntimeError('Lab DNS origin address read-back failed')
    return {'names': list(LAB_NAMES), 'origins': addresses, 'proxied': True, 'records_changed': changes}


def publish(trust, addresses):
    token, zone = cloudflare_preflight(LAB_COMPANY, trust, LAB_NAMES[0].split('.', 1)[1])
    return synchronize(Records(token, zone), addresses)


def remove_owned(records, addresses=None):
    """Withdraw only records belonging to the exact pair being destroyed."""
    nodes = node_names(LAB_COMPANY, addresses) if addresses else LAB_NODES
    if addresses is not None and len(addresses) != 2:
        raise ValueError('Both teardown addresses are required for DNS ownership checks')
    expected = ({'CertLocker ' + LAB_COMPANY + ' ' + node: address for node, address in addresses.items()}
                if addresses is not None else {})
    snapshots = preflight(records, nodes)
    if any(expected and row.get('content') != expected[row['comment']]
           for entries in snapshots.values() for row in entries):
        raise ValueError('DNS points to a different lab generation; refusing removal')
    removed = 0
    for name, entries in snapshots.items():
        for row in entries:
            try:
                records.request('DELETE', '/' + urllib.parse.quote(row['id'], safe=''))
            except RuntimeError:
                if any(item.get('id') == row['id'] for item in records.list(name)):
                    raise
            removed += 1
    if any(records.list(name) for name in LAB_NAMES):
        raise RuntimeError('Lab DNS removal could not be verified')
    return {'names': list(LAB_NAMES), 'records_removed': removed}
