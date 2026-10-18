import pytest
import sqlite3

import database.migrations as migrations
from database.db import get_connection, initialize_database
from tests.historical_migration_helpers import insert_scope
from database.inventory import create_device, create_scope_device, save_observation
from database.remote_sensors import RemoteSensorStore
from services.scope_authorization import HOSTNAME_CONFIRMATION_VERSION


def test_upgrade_29_preserves_existing_scope_and_device_evidence(monkeypatch, tmp_path):
    path = tmp_path / 'upgrade.db'
    current = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, 'MIGRATIONS', current[:29])
    initialize_database(path)
    stamp = '2026-10-12T00:00:00'
    with get_connection(path) as connection:
        network_id = connection.execute(
            "INSERT INTO networks (cidr,name,description,authorized,enabled,created_at,updated_at) VALUES (?,?,?,1,1,?,?)",
            ('192.168.1.0/24', 'Home', '', stamp, stamp),
        ).lastrowid
    network = {'id': network_id, 'cidr': '192.168.1.0/24'}
    device = create_device(stable_key=f"network:{network['id']}:ip:192.168.1.8", network_id=network['id'],
        mac_address=None, hostname='fixture', vendor=None, first_seen='2026-10-12T00:00:00',
        last_seen='2026-10-12T00:00:00', last_ip_address='192.168.1.8', status='ONLINE', identity_confidence='LOW', db_path=path)
    save_observation(device_id=device['id'], network_id=network['id'], ip_address='192.168.1.8',
        mac_address=None, hostname='fixture', vendor=None, status='ONLINE', observed_at=device['last_seen'], source='fixture', db_path=path)
    with get_connection(path) as connection:
        private = connection.execute("SELECT id FROM authorized_scopes WHERE scope_type='PRIVATE_NETWORK' AND canonical_target=?", (network['cidr'],)).fetchone()
        if private is None:
            private_scope = insert_scope(connection, scope_type='PRIVATE_NETWORK', target=network['cidr'], name='Home')
            connection.execute("INSERT INTO network_scope_links(network_id,scope_id) VALUES (?,?)", (network_id, private_scope['id']))
        public = insert_scope(connection, scope_type='PUBLIC_IPV4', target='8.8.8.8')
        cidr = insert_scope(connection, scope_type='PUBLIC_CIDR', target='8.8.8.8/29')
        hostname = insert_scope(connection, scope_type='HOSTNAME', target='example.test')
        connection.execute("UPDATE authorized_scopes SET resolution_verified_at=?,resolution_version='fixture',resolution_status='CURRENT' WHERE id=?", ('2026-10-12', hostname['id']))
        connection.execute("INSERT INTO scope_hostname_addresses(scope_id,ipv4_address,approved,approved_at,verified_at,resolution_version) VALUES (?, '8.8.8.8',1,?,?, 'fixture')", (hostname['id'], '2026-10-12', '2026-10-12'))
    for scope in (public, hostname):
        create_scope_device(scope['id'], ip_address='8.8.8.8', first_seen=device['first_seen'], last_seen=device['last_seen'], status='ONLINE', db_path=path)
    with get_connection(path) as c:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'")]
        before = {t: c.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables}
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 29
    monkeypatch.setattr(migrations, 'MIGRATIONS', current)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as c:
        assert {t: c.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables} == before
        assert c.execute('PRAGMA foreign_key_check').fetchall() == []
        assert c.execute('SELECT COUNT(*) FROM schema_migrations WHERE version=30').fetchone()[0] == 1
        for table in ('sites', 'remote_sensors', 'sensor_enrollment_tokens', 'remote_scope_sites', 'sensor_scope_assignments'):
            assert c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
    store = RemoteSensorStore(path)
    store.create_site('New site')
    initialize_database(path)
    assert len(store.list_sites()) == 1


def test_migration_30_rolls_back_on_failure(monkeypatch, tmp_path):
    path = tmp_path / 'rollback.db'
    current = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, 'MIGRATIONS', current[:29])
    initialize_database(path)
    monkeypatch.setattr(migrations, 'MIGRATIONS', current[:29] + ((30, current[29][1] + ('INVALID SQL',)),))
    with pytest.raises(sqlite3.OperationalError):
        initialize_database(path)
    with get_connection(path) as c:
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 29
        assert c.execute("SELECT name FROM sqlite_master WHERE name='sites'").fetchall() == []
    monkeypatch.setattr(migrations, 'MIGRATIONS', current)
    initialize_database(path)
