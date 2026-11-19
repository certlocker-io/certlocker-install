#!/usr/bin/env python3
"""Inspect only the disposable DB pair; never emit container environments or secrets."""
import argparse
import ipaddress
import json
import subprocess
import time

POSTGRES = "certlocker-uncloud-postgres"
PGPOOL = "certlocker-uncloud-pgpool"
IMAGES = {
    POSTGRES: "docker.io/bitnamilegacy/postgresql-repmgr@sha256:4786542acf26d47f83d1a636d3d5c54ffd5156a4cdbd3eb1678d750046c9bccb",
    PGPOOL: "docker.io/bitnamilegacy/pgpool@sha256:d3bf3910f148d7546df0762d1abed497cdeab01fdb239a337982e240a2d110ab",
}


def command(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if result.returncode:
        # Database or runtime stderr can include credentials; report only the operation.
        raise RuntimeError(f"{args[0]} operation failed with exit {result.returncode}")
    return result.stdout.strip()


def query(sql, host="127.0.0.1"):
    # Pgpool's local private listener is plaintext; PostgreSQL requires TLS here.
    sslmode = 'disable' if host == 'pgpool' else 'require'
    return command(["docker", "exec", "-e", "PGSSLMODE=" + sslmode, POSTGRES, "bash", "-ec",
                    'export PGPASSWORD="$(cat /run/lab-secrets/postgres)" PGCONNECT_TIMEOUT=5; exec psql "$@"',
                    "--", "-h", host, "-U", "postgres", "-d", "certlocker_lab",
                    "-v", "ON_ERROR_STOP=1", "-At", "-c", sql])


def inspect(name, mesh_ip):
    data = json.loads(command(["docker", "inspect", name]))[0]
    expected_ip = mesh_ip if name == POSTGRES else "127.0.0.1"
    assert data["Config"]["Image"] == IMAGES[name], "Unexpected image"
    assert data["State"]["Health"]["Status"] == "healthy", f"{name} is not healthy"
    networks = data['NetworkSettings']['Networks']
    assert set(networks) == {'uncloud'}, "Containers must use the Uncloud network directly"
    assert ipaddress.ip_address(networks['uncloud']['IPAddress']) in ipaddress.ip_network('10.210.0.0/16')
    assert data["Config"]["User"] == "1001:0", "Database must run as the image's non-root user"
    assert not data["HostConfig"]["Privileged"], "Privileged containers are not permitted"
    assert "ALL" in data["HostConfig"]["CapDrop"], "Capabilities must be dropped"
    assert "no-new-privileges:true" in data["HostConfig"]["SecurityOpt"], "Privilege escalation must be disabled"
    ports = data["HostConfig"]["PortBindings"]
    assert ports == {"5432/tcp": [{"HostIp": expected_ip, "HostPort": "5432"}]}, "Unexpected host exposure"
    config_dir = '/opt/bitnami/repmgr/conf' if name == POSTGRES else '/opt/bitnami/pgpool/conf'
    transient = data['HostConfig'].get('Tmpfs', {})
    assert config_dir in transient and '/tmp' in transient, 'Generated credential files must use memory-backed storage'
    for value in data['Config'].get('Env', []):
        key, _, content = value.partition('=')
        assert not (key.endswith('_PASSWORD') and content), 'Container metadata must not retain a plaintext password'
    # Persistent settings may contain paths/hashes, never runtime passwords.
    scan = '''set -eu
for file in /bitnami/postgresql/data/postgresql.auto.conf /opt/bitnami/pgpool/etc/pcp.conf; do
  if [ -f "$file" ]; then
    for secret in /run/lab-secrets/postgres /run/lab-secrets/repmgr /run/lab-secrets/pgpool; do
      if [ -s "$secret" ] && grep -Fq -f "$secret" "$file"; then exit 9; fi
    done
  fi
done'''
    command(['docker', 'exec', name, 'bash', '-ec', scan])
    return {"healthy": True, "host_binding": f"{expected_ip}:5432", 'generated_credentials_on_tmpfs': True,
            'persistent_settings_password_scan': 'passed'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    parser.add_argument("--primary-node", default="certlocker-a")
    parser.add_argument("--mesh-ip", required=True)
    parser.add_argument("--probe", help="Public synthetic UUID token for replication proof")
    args = parser.parse_args()
    assert ipaddress.ip_address(args.mesh_ip) in ipaddress.ip_network("10.210.0.0/16")
    report = {name: inspect(name, args.mesh_ip) for name in IMAGES}
    recovery = query("SELECT pg_is_in_recovery()")
    assert recovery == ("f" if args.node == args.primary_node else "t"), "Unexpected primary/standby roles"
    report["role"] = "primary" if recovery == "f" else "standby"
    assert query("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL OR (type <> 'local' AND auth_method='trust')") == "0", "Network authentication must require credentials"
    report["network_authentication_required"] = True
    assert query("SELECT pg_is_in_recovery()", host="pgpool") == "f", "Pgpool did not reach the writer"
    report["pgpool_reaches_primary"] = True
    if recovery == "f":
        value = query("SELECT count(*) FROM pg_stat_replication r JOIN pg_stat_ssl s USING(pid) WHERE r.state='streaming' AND s.ssl")
        assert value == "1", "Expected one TLS streaming standby"
        report["tls_streaming_standbys"] = 1
        report["replay_lag_bytes"] = int(query("SELECT coalesce(max(pg_wal_lsn_diff(pg_current_wal_lsn(),replay_lsn)),0)::bigint FROM pg_stat_replication"))
    else:
        assert query("SELECT count(*) FROM pg_stat_wal_receiver WHERE status='streaming'") == "1"
        report["wal_receiver_streaming"] = True
    if args.probe:
        import uuid
        probe = str(uuid.UUID(args.probe))
        if recovery == "f":
            # Synthetic data only, isolated DB, explicit installation smoke test.
            query("CREATE SCHEMA IF NOT EXISTS uncloud_lab; CREATE TABLE IF NOT EXISTS uncloud_lab.replication_probe (id uuid PRIMARY KEY, created_at timestamptz DEFAULT now()); "
                  f"INSERT INTO uncloud_lab.replication_probe(id) VALUES ('{probe}') ON CONFLICT DO NOTHING")
        for attempt in range(30):
            try:
                if query(f"SELECT count(*) FROM uncloud_lab.replication_probe WHERE id='{probe}'") == "1":
                    break
            except RuntimeError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Synthetic row did not replicate within 30 seconds")
        report["replication_probe"] = probe
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
