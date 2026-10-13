import json

import pytest
from fastapi.testclient import TestClient

import api.main as api
from database.remote_sensors import RemoteSensorStore
from database.networks import create_network
from database.scopes import get_scope_for_network
from services.remote_sensor_models import RemoteSensorAuthError


@pytest.fixture
def context(monkeypatch, tmp_path):
    path = tmp_path / 'remote-api.db'
    monkeypatch.setattr(api, 'DB_PATH', path)
    def forbidden(*args, **kwargs):
        raise AssertionError('No network/scanner/DNS behavior permitted')
    monkeypatch.setattr('services.scanner_adapters.nmap_adapter.subprocess.run', forbidden)
    client = TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 5050))
    return client, RemoteSensorStore(path)


def test_management_enrollment_read_secrecy_and_assignment(context):
    client, store = context
    site = client.post('/sites', json={'name': 'Home'}).json()
    assert client.get('/sites').json() == [site]
    assert client.get(f"/sites/{site['id']}").json() == site
    response = client.post(f"/sites/{site['id']}/sensor-enrollments", json={})
    assert response.status_code == 201
    assert response.headers['cache-control'] == 'no-store'
    invitation = response.json()
    issued = store.consume_enrollment(invitation['token'], name='A', platform='linux', version='1')
    sensor = issued.record
    assert sensor['status'] == 'PENDING'
    assert client.get(f"/sensors/{sensor['id']}").json() == sensor
    listing = client.get(f"/sites/{site['id']}/sensor-enrollments").json()
    assert listing[0]['consumed_at'] is not None
    payload = json.dumps(listing + client.get(f"/sites/{site['id']}/sensors").json())
    for secret in (invitation['token'], issued.secret, 'credential_hash', 'credential_salt', 'token_hash'):
        assert secret not in payload
    network = create_network('192.168.1.0/24', 'LAN', '', True, True, store.db_path)
    scope = get_scope_for_network(network['id'], store.db_path)
    route = f"/sensors/{sensor['id']}/scope-assignments"
    assigned = client.post(route, json={'scope_id': scope['id']})
    assert assigned.status_code == 200
    assert client.get(route).json() == [assigned.json()]
    assert client.post(route, json={'scope_id': scope['id'], 'target':'8.8.8.8'}).status_code == 422
    assert client.delete(f"{route}/{scope['id']}").status_code == 204
    assert client.get(route).json() == []
    assert client.delete(f"/sensors/{sensor['id']}/credential").status_code == 200
    assert client.patch(f"/sensors/{sensor['id']}", json={'enabled': True}).status_code == 400
    with pytest.raises(RemoteSensorAuthError):
        store.heartbeat(sensor['id'], issued.secret, platform='linux', version='1')
    assert client.patch(f"/sites/{site['id']}", json={'enabled': False}).json()['enabled'] is False
    assert client.post(f"/sites/{site['id']}/sensor-enrollments", json={}).status_code == 400


def test_revoked_enrollment_cannot_be_consumed(context):
    client, store = context
    site = store.create_site('Home')
    issued = client.post(f"/sites/{site['id']}/sensor-enrollments", json={}).json()
    assert client.delete(f"/sensor-enrollments/{issued['id']}").status_code == 200
    with pytest.raises(RemoteSensorAuthError):
        store.consume_enrollment(issued['token'], name='A', platform='windows', version='1')


@pytest.mark.parametrize('headers', [{'Origin':'https://untrusted.test'}, {'Origin':'null'}, {'Host':'untrusted.test'}, {'X-Forwarded-For':'127.0.0.1'}, {'Forwarded':'for=127.0.0.1'}])
def test_browser_and_proxy_access_rejected(context, headers):
    client, store = context
    assert client.post('/sites', json={'name':'Not allowed'}, headers=headers).status_code == 403
    assert store.list_sites() == []


def test_remote_peer_cannot_manage_even_with_sensor_credential(context):
    _, store = context
    site = store.create_site('Home')
    secret = store.create_enrollment(site['id'])
    sensor = store.consume_enrollment(secret.secret, name='A', platform='linux', version='1')
    client = TestClient(api.app, base_url='http://127.0.0.1', client=('192.168.1.8', 5555))
    response = client.post('/sites', json={'name':'No'}, headers={'Authorization': f'Bearer {sensor.secret}'})
    assert response.status_code == 403
    assert len(store.list_sites()) == 1


def test_no_execution_result_or_sensor_transport_routes(context):
    client, _ = context
    paths = client.get('/openapi.json').json()['paths']
    sensor_paths = [p for p in paths if p.startswith(('/sensors', '/sites', '/sensor-enrollments'))]
    assert sensor_paths
    assert all(not any(term in p for term in ('jobs','results','execute','scan','heartbeat','consume')) for p in sensor_paths)
    for path in ('/sensors/1/jobs', '/sensors/1/results', '/sensors/1/scan', '/sensors/enroll'):
        assert client.post(path, json={'target':'8.8.8.8'}).status_code in (404, 405)


def test_assignment_rejected_when_scope_not_confirmed(context):
    client, store = context
    site = store.create_site('Home')
    invite = store.create_enrollment(site['id'])
    sensor = store.consume_enrollment(invite.secret, name='A', platform='linux', version='1').record
    network = create_network('192.168.1.0/24', 'LAN', '', True, False, store.db_path)
    scope = get_scope_for_network(network['id'], store.db_path)
    assert client.post(f"/sensors/{sensor['id']}/scope-assignments", json={'scope_id':scope['id']}).status_code == 400
    assert store.list_assignments(sensor['id']) == []
