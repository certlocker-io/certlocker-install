#!/usr/bin/env python3
"""Generate fresh disposable database credentials/TLS identities; never print them."""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def generate(path, addresses, passwords=None):
    if len(addresses) != 2 or sorted(addresses)[1] != sorted(addresses)[0][:-1] + "b" or not sorted(addresses)[0].endswith("-a"):
        raise ValueError("Only the isolated lab pair is permitted")
    for value in addresses.values():
        if ipaddress.ip_address(value) not in ipaddress.ip_network("10.210.0.0/16"):
            raise ValueError("Certificate addresses must belong to the private Uncloud mesh")
    if path.exists():
        existing = json.loads(path.read_text())
        if existing["addresses"] != addresses:
            raise ValueError("Existing database identity differs; refusing to rotate it")
        if passwords is not None and existing['passwords'] != passwords:
            raise ValueError('Trust database credentials differ from the existing database; refusing rotation')
        return False
    bundle = generate_bundle(addresses, passwords)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(bundle, stream)
    return True


def generate_bundle(addresses, passwords):
    if len(addresses) != 2 or sorted(addresses)[1] != sorted(addresses)[0][:-1] + "b" or not sorted(addresses)[0].endswith("-a") or any(ipaddress.ip_address(v) not in ipaddress.ip_network("10.210.0.0/16") for v in addresses.values()):
        raise ValueError("Database identity requires the dedicated Uncloud mesh pair")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CertLocker disposable Uncloud lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=90))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    nodes = {}
    for name, address in addresses.items():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pg-" + name)]))
                .issuer_name(ca_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("pg-" + name), x509.IPAddress(ipaddress.ip_address(address))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        nodes[name] = {"certificate": leaf.public_bytes(serialization.Encoding.PEM).decode(),
                       "key": key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()).decode()}
    bundle = {"addresses": addresses, "nodes": nodes,
              "ca": ca.public_bytes(serialization.Encoding.PEM).decode(),
              "ca_key": ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
              "ca_serial": format(ca.serial_number, "x"),
              "passwords": passwords if passwords is not None else
              {name: secrets.token_hex(32) for name in ("postgres", "repmgr", "pgpool")}}
    return bundle


if __name__ == "__main__":
    passwords = json.load(sys.stdin) if '--passwords-stdin' in sys.argv else None
    if passwords is not None and (set(passwords) != {'postgres', 'repmgr', 'pgpool'} or
                                  not all(isinstance(value, str) and value for value in passwords.values())):
        raise ValueError('Three nonempty Trust database credentials are required')
    changed = generate(Path(sys.argv[1]), json.loads(sys.argv[2]), passwords)
    print("created" if changed else "preserved")
