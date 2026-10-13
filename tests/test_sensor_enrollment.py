"""10B registration/authentication tests use in-process requests and temporary DBs."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import base64
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.remote_sensors import register_remote_routes
from api.sensor_enrollment import register_machine_routes
from database.db import get_connection, initialize_database
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.scopes import get_scope_for_network
from services.remote_sensor_models import Capability


@pytest.fixture
def context(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('No scanner or subprocess permitted')
    monkeypatch.setattr('services.scanner_adapters.nmap_adapter.subprocess.run', forbidden)
    now = [datetime(2026, 10, 13, tzinfo=timezone.utc)]
    store = RemoteSensorStore(tmp_path / 'enrollment.db', clock=lambda: now[0])
    app = FastAPI()
    register_remote_routes(app, lambda: store)
    register_machine_routes(app, lambda: store)
    with TestClient(app, base_url='https://core.test', client=('192.168.1.8', 5555)) as remote:
        with TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 5556)) as admin:
            site = admin.post('/sites', json={'name': 'Home'}).json()
            yield store, site, now, remote, admin


def invitation(context):
    _, site, _, _, admin = context
    response = admin.post(f"/sites/{site['id']}/sensor-enrollments", json={'ttl_seconds': 60})
    assert response.status_code == 201
    assert response.headers['cache-control'] == 'no-store'
    return response.json()


def payload(token, sensor_uuid=None):
    return dict(enrollment_token=token, sensor_uuid=sensor_uuid or str(uuid.uuid4()),
                sensor_name='Sensor A', platform='linux', version='1',
                capabilities=[c.value for c in Capability])


def enroll(context):
    response = context[3].post('/sensor-enrollment/register', json=payload(invitation(context)['token']))
    assert response.status_code == 201
    assert response.headers['cache-control'] == 'no-store'
    return response.json()


def auth(sensor):
    return {'Authorization': f"Bearer {sensor['credential']}", 'X-Sensor-UUID': sensor['sensor_uuid']}


SELF_KEYS = {'id', 'sensor_uuid', 'site_id', 'name', 'platform', 'version', 'enabled',
             'capabilities', 'registered_at', 'last_seen_at', 'status'}


def test_creation_registration_secrecy_and_self(context, caplog):
    store, site, now, remote, admin = context
    invite = invitation(context)
    assert len(base64.urlsafe_b64decode(invite['token'] + '=')) == 32
    assert invitation(context)['token'] != invite['token']
    assert invite['site_id'] == site['id']
    assert datetime.fromisoformat(invite['expires_at']) - now[0] == timedelta(seconds=60)
    body = payload(invite['token'])
    response = remote.post('/sensor-enrollment/register', json=body)
    assert response.status_code == 201
    sensor = response.json()
    assert set(sensor) == SELF_KEYS | {'credential'}
    assert len(base64.urlsafe_b64decode(sensor['credential'] + '=')) == 32
    assert sensor['credential'] != invite['token']
    assert sensor['sensor_uuid'] == body['sensor_uuid']
    assert sensor['site_id'] == site['id'] and sensor['enabled'] is True
    assert sensor['registered_at'] == now[0].isoformat()
    assert sensor['capabilities'] == sorted(c.value for c in Capability)
    read = remote.get('/sensor/self', headers=auth(sensor))
    assert read.status_code == 200 and set(read.json()) == SELF_KEYS
    assert read.headers['cache-control'] == 'no-store'
    assert read.json()['last_seen_at'] is None
    listing = admin.get(f"/sites/{site['id']}/sensor-enrollments")
    assert listing.json()[0]['consumed_at'] == now[0].isoformat()
    with get_connection(store.db_path) as c:
        persisted = '\n'.join(c.iterdump())
        assert c.execute('SELECT length(token_hash) FROM sensor_enrollment_tokens').fetchone()[0] == 64
    safe = listing.text + read.text + admin.get(f"/sensors/{sensor['id']}").text + caplog.text
    for secret in (invite['token'], sensor['credential']):
        assert secret not in persisted and secret not in safe
    for field in ('credential_hash', 'credential_salt', 'token_hash', 'credential_iterations'):
        assert field not in safe
    assert store.list_assignments(sensor['id']) == []


@pytest.mark.parametrize('failure', ['unknown', 'expired', 'revoked', 'used', 'disabled_site'])
def test_registration_fail_closed(context, failure):
    store, site, now, remote, _ = context
    invite = invitation(context)
    body = payload(invite['token'])
    if failure == 'unknown':
        body['enrollment_token'] = 'x' * 43
    elif failure == 'expired':
        now[0] += timedelta(seconds=60)
    elif failure == 'revoked':
        store.revoke_enrollment(invite['id'])
    elif failure == 'disabled_site':
        store.set_site_enabled(site['id'], False)
    elif failure == 'used':
        assert remote.post('/sensor-enrollment/register', json=body).status_code == 201
    before = store.list_sensors(site['id'])
    response = remote.post('/sensor-enrollment/register', json=body)
    assert response.status_code == 400
    assert response.json() == {'detail': 'Registration rejected.'}
    assert store.list_sensors(site['id']) == before


@pytest.mark.parametrize('extra', ['site_id', 'scope_id', 'target', 'command', 'shell', 'scanner_flags', 'enabled'])
def test_registration_cannot_expand_authority(context, extra):
    store, site, _, remote, _ = context
    invite = invitation(context)
    response = remote.post('/sensor-enrollment/register', json={**payload(invite['token']), extra: 'untrusted'})
    assert response.status_code == 422
    assert invite['token'] not in response.text
    assert store.list_sensors(site['id']) == []
    assert store.list_enrollments(site['id'])[0]['consumed_at'] is None


@pytest.mark.parametrize('change', [
    {'sensor_uuid': 'bad'}, {'sensor_name': ' '}, {'platform': 'x' * 65},
    {'version': 'x' * 65}, {'enrollment_token': 'short'},
    {'capabilities': ['HOST_DISCOVERY'] * 5},
    *({'capabilities': [value]} for value in ('RUN_COMMAND', 'SHELL', 'EXEC', 'SCRIPT', 'ARBITRARY_NMAP', 'UNKNOWN')),
])
def test_registration_metadata_bounds(context, change):
    store, site, _, remote, _ = context
    body = {**payload(invitation(context)['token']), **change}
    response = remote.post('/sensor-enrollment/register', json=body)
    assert response.status_code in (400, 422)
    assert body['enrollment_token'] not in response.text
    assert store.list_sensors(site['id']) == []


def test_duplicate_uuid_is_conflict_without_consumption(context):
    store, site, _, remote, _ = context
    original = enroll(context)
    other_site = store.create_site('Other')
    invite = store.create_enrollment(other_site['id'])
    response = remote.post('/sensor-enrollment/register', json=payload(invite.secret, original['sensor_uuid'].upper()))
    assert response.status_code == 409
    assert store.list_enrollments(other_site['id'])[0]['consumed_at'] is None
    assert store.list_sensors(other_site['id']) == []
    assert remote.get('/sensor/self', headers=auth(original)).status_code == 200
    assert len(store.list_sensors(site['id'])) == 1
    assert remote.post('/sensor-enrollment/register', json=payload(invite.secret)).status_code == 201


@pytest.mark.parametrize('same_token', [True, False])
def test_concurrent_registration(context, same_token):
    store, site, _, remote, _ = context
    first = invitation(context)['token']
    second = first if same_token else invitation(context)['token']
    identity = str(uuid.uuid4())
    bodies = [payload(first, identity), payload(second, str(uuid.uuid4()) if same_token else identity)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda body: remote.post('/sensor-enrollment/register', json=body), bodies))
    assert sorted(r.status_code for r in responses) == [201, 400 if same_token else 409]
    assert len(store.list_sensors(site['id'])) == 1
    assert sum(r['consumed_at'] is not None for r in store.list_enrollments(site['id'])) == 1


@pytest.mark.parametrize('kind', ['none', 'unknown', 'uuid_only', 'site_only', 'enrollment', 'other_sensor', 'wrong_uuid', 'oversize', 'basic'])
def test_authentication_rejects_invalid_proof(context, kind):
    _, site, _, remote, _ = context
    sensor = enroll(context)
    headers = auth(sensor)
    if kind == 'none':
        headers = {}
    elif kind == 'uuid_only':
        headers.pop('Authorization')
    elif kind == 'site_only':
        headers = {'X-Site-ID': str(site['id'])}
    elif kind == 'wrong_uuid':
        headers['X-Sensor-UUID'] = str(uuid.uuid4())
    else:
        secret = {'unknown': 'x' * 43, 'oversize': 'x' * 129, 'basic': sensor['credential']}.get(kind)
        if kind == 'enrollment':
            secret = invitation(context)['token']
        elif kind == 'other_sensor':
            secret = enroll(context)['credential']
        headers['Authorization'] = f"{'Basic' if kind == 'basic' else 'Bearer'} {secret}"
    for method, path, kwargs in [('get', '/sensor/self', {}), ('post', '/sensor/heartbeat', {'json': {'platform': 'linux', 'version': '2'}})]:
        response = getattr(remote, method)(path, headers=headers, **kwargs)
        assert response.status_code == 401
        assert response.headers['www-authenticate'] == 'Bearer'
        assert response.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('state', ['disabled', 'revoked', 'site_disabled'])
def test_revocation_blocks_self_and_heartbeat_immediately(context, state):
    store, site, _, remote, admin = context
    sensor = enroll(context)
    if state == 'disabled':
        assert admin.patch(f"/sensors/{sensor['id']}", json={'enabled': False}).status_code == 200
    elif state == 'revoked':
        assert admin.delete(f"/sensors/{sensor['id']}/credential").status_code == 200
        assert admin.patch(f"/sensors/{sensor['id']}", json={'enabled': True}).status_code == 400
    else:
        store.set_site_enabled(site['id'], False)
    assert remote.get('/sensor/self', headers=auth(sensor)).status_code == 401
    assert remote.post('/sensor/heartbeat', headers=auth(sensor), json={'platform': 'linux', 'version': '2'}).status_code == 401
    assert store.get_sensor(sensor['id'])['last_seen_at'] is None


def test_heartbeat_time_and_assignments(context):
    store, _, now, remote, _ = context
    sensor = enroll(context)
    network = create_network('192.168.1.0/24', 'LAN', '', True, True, store.db_path)
    scope = get_scope_for_network(network['id'], store.db_path)
    assignment = store.assign_scope(sensor['id'], scope['id'])
    now[0] += timedelta(seconds=10)
    response = remote.post('/sensor/heartbeat', headers=auth(sensor), json={'platform': 'windows', 'version': '2', 'capabilities': ['LOG_COLLECTION']})
    assert response.status_code == 200
    assert response.json()['last_seen_at'] == now[0].isoformat()
    assert response.json()['status'] == 'ONLINE'
    assert response.json()['capabilities'] == ['LOG_COLLECTION']
    assert set(response.json()) == SELF_KEYS
    for key, value in [('timestamp', '2000-01-01'), ('status', 'ONLINE'), ('scope_id', scope['id']), ('target', '8.8.8.8'), ('capabilities', ['SHELL'])]:
        assert remote.post('/sensor/heartbeat', headers=auth(sensor), json={'platform': 'linux', 'version': '3', key: value}).status_code == 422
    assert store.list_assignments(sensor['id']) == [assignment]
    assert get_scope_for_network(network['id'], store.db_path) == scope
    assert store.get_sensor(sensor['id'])['version'] == '2'
    now[0] += timedelta(seconds=301)
    assert remote.get('/sensor/self', headers=auth(sensor)).json()['status'] == 'OFFLINE'


def test_no_management_privilege_or_execution(context):
    store, site, _, remote, admin = context
    sensor = enroll(context)
    for client in (remote, admin):
        assert client.post(f"/sites/{site['id']}/sensor-enrollments", headers=auth(sensor), json={}).status_code == 403
        assert client.post(f"/sensors/{sensor['id']}/scope-assignments", headers=auth(sensor), json={'scope_id': 1}).status_code == 403
    for suffix in ('jobs', 'results', 'scan', 'execute', 'shell', 'scope-assignments'):
        assert remote.post(f'/sensor/{suffix}', headers=auth(sensor), json={'target': '8.8.8.8'}).status_code in (404, 405)
    machine_paths = {p for p in remote.get('/openapi.json').json()['paths'] if p.startswith(('/sensor/', '/sensor-enrollment/'))}
    assert machine_paths == {'/sensor/self', '/sensor/heartbeat', '/sensor-enrollment/register'}
    assert store.list_assignments(sensor['id']) == []


@pytest.mark.parametrize('headers', [{'Origin': 'https://core.test'}, {'X-Forwarded-Proto': 'https'}, {'Forwarded': 'proto=https'}])
def test_machine_transport_rejects_browser_and_proxy(context, headers):
    response = context[3].post('/sensor-enrollment/register', headers=headers, json=payload(invitation(context)['token']))
    assert response.status_code == 403


def test_https_required_remote_and_no_query_credentials(context):
    _, _, _, remote, admin = context
    invite = invitation(context)
    with TestClient(remote.app, base_url='http://core.test', client=('192.168.1.8', 5555)) as plain:
        assert plain.post('/sensor-enrollment/register', json=payload(invite['token'])).status_code == 403
    assert admin.post('/sensor-enrollment/register', json=payload(invite['token'])).status_code == 201
    assert remote.get('/sensor/self?credential=not-accepted').status_code == 400


def test_initialization_preserves_10a_rows_and_credential(context):
    store, site, _, remote, _ = context
    old_invite = store.create_enrollment(site['id'])
    old_sensor = store.consume_enrollment(old_invite.secret, name='10A', platform='linux', version='1')
    network = create_network('192.168.2.0/24', 'LAN', '', True, True, store.db_path)
    scope = get_scope_for_network(network['id'], store.db_path)
    store.assign_scope(old_sensor.record['id'], scope['id'])
    invitation(context)
    with get_connection(store.db_path) as c:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        before = {t: c.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables}
    initialize_database(store.db_path)
    initialize_database(store.db_path)
    with get_connection(store.db_path) as c:
        assert {t: c.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables} == before
        assert c.execute('PRAGMA foreign_key_check').fetchall() == []
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 30
    assert remote.get('/sensor/self', headers=auth({**old_sensor.record, 'credential': old_sensor.secret})).status_code == 200


def test_registration_write_failure_rolls_back_identity_and_token(context):
    store, site, _, remote, _ = context
    invite = invitation(context)
    with get_connection(store.db_path) as c:
        c.execute("""CREATE TRIGGER fail_consumption BEFORE UPDATE ON sensor_enrollment_tokens
                     BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError, match='injected failure'):
        remote.post('/sensor-enrollment/register', json=payload(invite['token']))
    assert store.list_sensors(site['id']) == []
    assert store.list_enrollments(site['id'])[0]['consumed_at'] is None
    with get_connection(store.db_path) as c:
        c.execute('DROP TRIGGER fail_consumption')
    assert remote.post('/sensor-enrollment/register', json=payload(invite['token'])).status_code == 201


def test_consumed_token_and_duplicate_headers_cannot_authenticate(context):
    _, _, _, remote, _ = context
    invite = invitation(context)
    sensor = remote.post('/sensor-enrollment/register', json=payload(invite['token'])).json()
    headers = auth(sensor)
    headers['Authorization'] = f"Bearer {invite['token']}"
    assert remote.get('/sensor/self', headers=headers).status_code == 401
    for key in ('Authorization', 'X-Sensor-UUID'):
        headers = list(auth(sensor).items()) + [(key, auth(sensor)[key])]
        assert remote.get('/sensor/self', headers=headers).status_code == 401


def test_heartbeat_rechecks_revocation_in_write_transaction(context, monkeypatch):
    store, _, _, remote, _ = context
    sensor = enroll(context)
    original = store.authenticate_sensor
    def authenticate_then_revoke(*args):
        authenticated = original(*args)
        store.revoke_sensor(authenticated['id'])
        return authenticated
    monkeypatch.setattr(store, 'authenticate_sensor', authenticate_then_revoke)
    assert remote.post('/sensor/heartbeat', headers=auth(sensor), json={'platform': 'linux', 'version': '2'}).status_code == 401
    assert store.get_sensor(sensor['id'])['last_seen_at'] is None


def test_main_app_wires_machine_routes(tmp_path, monkeypatch):
    import api.main as api
    monkeypatch.setattr(api, 'DB_PATH', tmp_path / 'main.db')
    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 5555)) as client:
        site = client.post('/sites', json={'name': 'Home'}).json()
        invite = client.post(f"/sites/{site['id']}/sensor-enrollments", json={}).json()
        response = client.post('/sensor-enrollment/register', json=payload(invite['token']))
        assert response.status_code == 201
        sensor = response.json()
        assert client.get('/sensor/self', headers=auth(sensor)).json()['id'] == sensor['id']
        assert client.post('/sensor/heartbeat', headers=auth(sensor), json={'platform': 'linux', 'version': '2'}).status_code == 200
