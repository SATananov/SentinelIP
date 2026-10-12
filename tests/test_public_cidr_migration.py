import database.migrations as migrations
from database.db import initialize_database, get_connection
from database.scopes import create_scope, create_hostname_scope
from database.inventory import create_scope_device, get_device
from database.networks import create_network
from services.scope_authorization import HOSTNAME_CONFIRMATION_VERSION


def test_upgrade_from_28_preserves_scopes_devices_and_is_idempotent(monkeypatch, tmp_path):
    path = tmp_path / 'upgrade.db'
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, 'MIGRATIONS', all_migrations[:28])
    create_network('192.168.1.0/24', 'Fixture', '', True, True, path)
    public = create_scope(scope_type='PUBLIC_IPV4', canonical_target='8.8.8.8', authorized=True,
        enabled=True, authorization_confirmed_at='2026-10-12',
        authorization_confirmation_version='public_ipv4_authorization_v1', authorization_source='fixture', db_path=path)
    hostname = create_hostname_scope(canonical_hostname='example.test', approved_addresses=['8.8.8.8'],
        authorization_confirmed_at='2026-10-12', authorization_confirmation_version=HOSTNAME_CONFIRMATION_VERSION,
        authorization_source='fixture', resolution_version='fixture', db_path=path)
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
