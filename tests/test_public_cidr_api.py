import sqlite3
from types import SimpleNamespace

import pytest

import api.main as api
from database.db import get_connection, initialize_database
from database.inventory import create_scope_device
from database.scopes import create_scope, get_scope
from services.public_cidr_policy import PUBLIC_CIDR_CONFIRMATION_VERSION
from local_operator_client import make_local_test_client


@pytest.fixture
def context(monkeypatch, tmp_path):
    path = tmp_path / 'cidr.db'
    initialize_database(path)
    monkeypatch.setattr(api, 'DB_PATH', path)
    def forbidden(*args, **kwargs):
        raise AssertionError('No real subprocess or scan is permitted in this test')
    monkeypatch.setattr('services.scanner_adapters.nmap_adapter.subprocess.run', forbidden)
    return make_local_test_client(api.app), path


def payload(target='8.8.8.7/29', **changes):
    return dict(target=target, name='Fixture', description='Synthetic test only',
                authorization_confirmed=True,
                authorization_confirmation_version=PUBLIC_CIDR_CONFIRMATION_VERSION) | changes


def test_preview_and_create_are_non_scanning_and_explicit(context):
    client, path = context
    preview = client.post('/scopes/public-cidr/preview', json={'target': '8.8.8.7/29'})
    assert preview.status_code == 200
    assert preview.json() == dict(canonical_target='8.8.8.0/29', address_count=8,
                                  maximum_addresses=8, enumeration='ALL_ADDRESSES')
    assert client.get('/scopes').json() == []
    created = client.post('/scopes/public-cidr', json=payload())
    assert created.status_code == 201
    scope = created.json()
    assert scope['scope_type'] == 'PUBLIC_CIDR'
    assert scope['canonical_target'] == '8.8.8.0/29'
    assert scope['address_count'] == 8
    assert scope['network_id'] is None
    assert scope['authorized'] is True and scope['enabled'] is True
    assert scope['authorization_confirmed_at']
    assert scope['authorization_confirmation_version'] == PUBLIC_CIDR_CONFIRMATION_VERSION
    assert scope['authorization_source'] == 'api_explicit_public_cidr_confirmation'
    assert client.get(f"/scopes/{scope['id']}").json() == scope
    assert client.get('/scopes').json() == [scope]
    assert client.post('/scopes/public-cidr', json=payload('8.8.8.0/29')).status_code == 409
    with get_connection(path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM networks').fetchone()[0] == 0
        assert conn.execute('SELECT COUNT(*) FROM scope_cidr_addresses').fetchone()[0] == 8


@pytest.mark.parametrize('changes', [
    {'authorization_confirmed': False}, {'authorization_confirmed': 'true'},
    {'authorization_confirmation_version': 'old'}, {'target': '8.8.8.0/28'},
    {'target': '10.0.0.0/29'}, {'target': '8.8.8.8'}, {'target': '2001:4860::/32'},
])
def test_creation_rejects_before_any_scanner(context, changes):
    client, _ = context
    assert client.post('/scopes/public-cidr', json=payload() | changes).status_code == 422
    assert client.get('/scopes').json() == []


def test_confirmation_version_is_required(context):
    client, _ = context
    request = payload()
    del request['authorization_confirmation_version']
    assert client.post('/scopes/public-cidr', json=request).status_code == 422


@pytest.mark.parametrize('column,value', [
    ('scope_type', 'PRIVATE_NETWORK'), ('enabled', 0), ('authorized', 0),
    ('authorization_confirmed_at', ''), ('authorization_confirmation_version', 'unknown'),
    ('canonical_target', '8.8.8.0/28'), ('canonical_target', '10.0.0.0/29'),
    ('canonical_target', '8.8.8.1/29'), ('canonical_target', 'bad'),
    ('canonical_target', '1.1.1.0/29'),
])
def test_scan_gates_persisted_state_before_scanner(context, monkeypatch, column, value):
    client, path = context
    scope = client.post('/scopes/public-cidr', json=payload()).json()
    with get_connection(path) as conn:
        conn.execute(f'UPDATE authorized_scopes SET {column}=? WHERE id=?', (value, scope['id']))
    def forbidden_constructor():
        raise AssertionError('Invalid scope must be rejected before constructing scanner')
    monkeypatch.setattr(api, 'NmapHostDiscoveryScanner', forbidden_constructor)
    assert client.post(f"/scopes/{scope['id']}/discover").status_code == 403


def test_missing_membership_rejected(context):
    client, path = context
    scope = client.post('/scopes/public-cidr', json=payload()).json()
    with get_connection(path) as conn:
        conn.execute('DELETE FROM scope_cidr_addresses WHERE scope_id=?', (scope['id'],))
    assert client.post(f"/scopes/{scope['id']}/discover").status_code == 403


def test_exact_addresses_commands_inventory_and_existing_reviews(context, monkeypatch):
    client, path = context
    scope = client.post('/scopes/public-cidr', json=payload()).json()
    commands = []
    def fake_run(command, **kwargs):
        commands.append(command)
        assert kwargs['shell'] is False and kwargs['timeout'] <= 45
        assert '-n' in command
        assert not {'-sS', '-A', '-O', '-p-', '-sU', '--script'}.intersection(command)
        address = command[3] if '-sn' in command else command[-1]
        assert address in [f'8.8.8.{i}' for i in range(8)]
        assert '/' not in address
        if '-sn' not in command:
            assert '-sT' in command and '--version-light' in command
            assert command[command.index('--max-retries') + 1] == '2'
        ports = '' if '-sn' in command else '<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports>'
        return SimpleNamespace(returncode=0, stderr='', stdout=f'<nmaprun><host><status state="up"/><address addr="{address}" addrtype="ipv4"/>{ports}</host></nmaprun>')
    monkeypatch.setattr('services.scanner_adapters.nmap_adapter.subprocess.run', fake_run)
    # Unexpected body/query content cannot replace the persisted target.
    result = client.post(f"/scopes/{scope['id']}/discover?target=1.1.0.0/16", json={'target': '1.1.0.0/16'})
    assert result.status_code == 200, result.text
    data = result.json()
    assert data['address_count'] == 8 and len(data['devices']) == 8
    assert len(commands) == 16
    assert [c[3] for c in commands if '-sn' in c] == [f'8.8.8.{i}' for i in range(8)]
    for asset in data['assets']:
        device = asset['device']
        assert device['network_id'] is None and device['scope_id'] == scope['id']
        assert device['stable_key'] == f"scope:{scope['id']}:ipv4:{device['last_ip_address']}"
        assert asset['findings'][0]['finding_type'] == 'PLAINTEXT_SERVICE'
        assert asset['findings'][0]['scope_id'] == scope['id']
        for suffix, key in [('ports', 'ports'), ('services', 'services'), ('findings', 'findings'), ('cve-matches', 'cve_matches')]:
            assert client.get(f"/devices/{device['id']}/{suffix}").json() == asset[key]
    device = data['devices'][0]
    assert client.post(f"/scopes/{scope['id']}/devices/{device['id']}/discover-services").status_code == 200
    assert len(commands) == 17
    assert len(client.post(f"/scopes/{scope['id']}/discover").json()['devices']) == 8
    assert len(client.get(f"/scopes/{scope['id']}/devices").json()) == 8
    with get_connection(path) as conn:
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
        assert conn.execute('SELECT COUNT(*) FROM networks').fetchone()[0] == 0
    operation = client.get('/openapi.json').json()['paths']['/scopes/{scope_id}/discover']['post']
    assert 'requestBody' not in operation
    assert [p['name'] for p in operation['parameters']] == ['scope_id']


def test_scope_identity_and_membership_integrity(context):
    client, path = context
    scopes = [client.post('/scopes/public-cidr', json=payload(target)).json()
              for target in ('8.8.8.0/29', '8.8.8.0/32')]
    devices = [create_scope_device(s['id'], ip_address='8.8.8.0', first_seen='2026-10-12',
                last_seen='2026-10-12', status='ONLINE', db_path=path) for s in scopes]
    assert devices[0]['id'] != devices[1]['id']
    assert devices[0]['stable_key'] != devices[1]['stable_key']
    with pytest.raises(ValueError):
        create_scope_device(scopes[0]['id'], ip_address='1.1.1.1', first_seen='2026-10-12',
                            last_seen='2026-10-12', status='ONLINE', db_path=path)
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as conn:
        conn.execute('UPDATE devices SET last_ip_address=? WHERE id=?', ('1.1.1.1', devices[0]['id']))
