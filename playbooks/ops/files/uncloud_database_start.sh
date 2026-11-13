#!/bin/bash
# A returning database must discover a live writer before the image can select
# its role. Otherwise the image treats an unavailable mesh as permission to
# resume an obsolete primary. A simultaneous total outage stays stopped until
# an operator establishes the authoritative writer; this is not quorum/fencing.
set -euo pipefail

peer_is_writer() {
    local result
    result="$(PGPASSWORD="$(cat /run/lab-secrets/postgres)" PGCONNECT_TIMEOUT=3 PGSSLMODE=require \
        psql -h "$UNCLOUD_DB_PEER" -U postgres -d repmgr -Atq -v ON_ERROR_STOP=1 \
        -c "SELECT pg_is_in_recovery()::text || '|' || (SELECT count(*) FROM repmgr.nodes WHERE active AND type='primary')::text || '|' || COALESCE((SELECT node_id::text FROM repmgr.nodes WHERE active AND type='primary' ORDER BY node_id LIMIT 1),'');" \
        2>/dev/null)" || return 1
    [[ "$result" == "false|1|$UNCLOUD_DB_PEER_ID" ]]
}

peer_settings_valid() {
    [[ "${UNCLOUD_DB_PEER_ID:-}" =~ ^[12]$ && "${UNCLOUD_DB_PEER:-}" =~ ^pg-[a-z0-9][a-z0-9-]*-[ab]$ ]]
}

main() {
    if [[ -s /bitnami/postgresql/data/PG_VERSION ]]; then
        peer_settings_valid || exit 1
        printf '%s\n' 'Waiting for a verified peer writer before rejoining the database.'
        until peer_is_writer; do sleep 3; done
        printf '%s\n' 'Peer writer verified; starting native database rejoin.'
    fi
    exec /opt/bitnami/scripts/postgresql-repmgr/entrypoint.sh "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
