"""Built-in CertLocker updater access and optional customer monitoring access."""
import ipaddress

CERTLOCKER_UPDATER_CIDR = '88.81.117.228/32'
CERTLOCKER_UPDATER_CIDRS = (CERTLOCKER_UPDATER_CIDR, '185.88.0.182/32')
CERTLOCKER_UPDATER_LABEL = 'certlocker updater'


def customer_cidrs(value):
    """Accept comma-separated IPv4 addresses or individual /32 CIDRs."""
    result = set()
    for item in value.split(','):
        if not item.strip():
            continue
        network = ipaddress.ip_network(item.strip(), strict=True)
        if network.version != 4 or network.prefixlen != 32:
            raise ValueError('Use individual IPv4 addresses or /32 CIDRs, separated by commas')
        result.add(str(network))
    return sorted(result)


def with_updater(cidrs):
    return sorted(set(cidrs) | set(CERTLOCKER_UPDATER_CIDRS))


def monitoring_access(configured, *, interactive=False, supplied=None):
    additional = list(configured or [])
    if supplied is not None:
        additional = customer_cidrs(supplied)
    elif interactive:
        current = ','.join(cidr for cidr in additional if cidr not in CERTLOCKER_UPDATER_CIDRS)
        while True:
            answer = input('Additional customer VPN / whitelist IPv4 addresses, comma-separated'
                           + (f' [{current}]' if current else ' [optional]') + ': ').strip()
            try:
                additional = customer_cidrs(answer or current)
                break
            except ValueError:
                print('Enter individual IPv4 addresses or /32 CIDRs separated by commas.')
    return with_updater(additional)
