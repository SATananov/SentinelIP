import database.migrations as migrations
from database.db import initialize_database, get_connection
from database.inventory import create_scope_device, get_device
from tests.historical_migration_helpers import insert_scope


def test_upgrade_from_28_preserves_scopes_devices_and_is_idempotent(monkeypatch, tmp_path):
    path = tmp_path / 'upgrade.db'
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, 'MIGRATIONS', all_migrations[:28])
    initialize_database(path)
    stamp = '2026-10-12'
    with get_connection(path) as conn:
        network_id = conn.execute(
            "INSERT INTO networks (cidr,name,description,authorized,enabled,created_at,updated_at) VALUES (?,?,?,1,1,?,?)",
            ('192.168.1.0/24', 'Fixture', '', stamp, stamp),
        ).lastrowid
        private = insert_scope(conn, scope_type='PRIVATE_NETWORK', target='192.168.1.0/24', stamp=stamp)
        conn.execute("INSERT INTO network_scope_links(network_id,scope_id) VALUES (?,?)", (network_id, private['id']))
        public = insert_scope(conn, scope_type='PUBLIC_IPV4', target='8.8.8.8', stamp=stamp)
        hostname = insert_scope(conn, scope_type='HOSTNAME', target='example.test', stamp=stamp)
        conn.execute("UPDATE authorized_scopes SET resolution_verified_at=?,resolution_version=?,resolution_status='CURRENT' WHERE id=?",
                     (stamp, 'fixture', hostname['id']))
        conn.execute("INSERT INTO scope_hostname_addresses(scope_id,ipv4_address,approved,approved_at,verified_at,resolution_version) VALUES (?, '8.8.8.8',1,?,?,?)",
                     (hostname['id'], stamp, stamp, 'fixture'))
    devices = [create_scope_device(scope['id'], ip_address='8.8.8.8', first_seen='2026-10-12',
        last_seen='2026-10-12', status='ONLINE', db_path=path) for scope in (public, hostname)]
    with get_connection(path) as conn:
        before = conn.execute('SELECT * FROM authorized_scopes ORDER BY id').fetchall()
    monkeypatch.setattr(migrations, 'MIGRATIONS', all_migrations)
    initialize_database(path)
    initialize_database(path)
    assert [get_device(device['id'], path) for device in devices] == devices
    with get_connection(path) as conn:
        assert conn.execute('SELECT * FROM authorized_scopes ORDER BY id').fetchall() == before
        assert conn.execute('SELECT COUNT(*) FROM scope_cidr_addresses').fetchone()[0] == 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
        assert conn.execute('SELECT COUNT(*) FROM schema_migrations WHERE version=29').fetchone()[0] == 1
