import json

import pytest
from fastapi.testclient import TestClient

import api.main as api
from api.remote_sensors import local_management
from database.db import get_connection
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.scopes import get_scope_for_network
from services.remote_sensor_models import RemoteSensorAuthError


@pytest.fixture
def context(monkeypatch, tmp_path):
    path = tmp_path / 'sensor-management.db'
    monkeypatch.setattr(api, 'DB_PATH', path)
    client = TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 5050))
    return client, RemoteSensorStore(path)


def enroll(store, site_id, name='Sensor'):
    invite = store.create_enrollment(site_id)
    return invite, store.consume_enrollment(
        invite.secret, name=name, platform='declared-linux', version='1',
        reported_capabilities=['HOST_DISCOVERY'],
    )


def network_scope(store, cidr='192.168.17.0/24', name='Office LAN'):
    network = create_network(cidr, name, '', True, True, store.db_path)
    return get_scope_for_network(network['id'], store.db_path)


def test_store_eligible_scope_projection_returns_only_valid_bounded_candidates(tmp_path):
    store = RemoteSensorStore(tmp_path / 'eligible-store.db')
    site = store.create_site('North')
    _, sensor = enroll(store, site['id'])
    valid = network_scope(store)
    disabled = network_scope(store, '192.168.18.0/24', 'Disabled LAN')
    with get_connection(store.db_path) as connection:
        connection.execute('UPDATE authorized_scopes SET enabled=0 WHERE id=?', (disabled['id'],))
    page = store.list_eligible_assignment_scopes(site['id'], sensor.record['id'], limit=1, offset=0)
    assert [item['id'] for item in page['items']] == [valid['id']]
    assert page['has_more'] is False
    assert page['items'][0]['scope_type'] == 'PRIVATE_NETWORK'
    assert store.list_fleet_sensors()['items'][0]['assignment_count'] == 0
    assert store.assign_scope(sensor.record['id'], valid['id'])['scope_name'] == 'Office LAN'
    assert store.list_fleet_sensors()['items'][0]['assignment_count'] == 1
    after_assignment = store.list_eligible_assignment_scopes(site['id'], sensor.record['id'])
    assert after_assignment['items'] == []
    with get_connection(store.db_path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM remote_sensor_tasks').fetchone()[0] == 0
    with pytest.raises(LookupError):
        store.list_eligible_assignment_scopes(site['id'], 99999)


def test_eligible_sensor_scope_projection_is_bounded_site_safe_and_policy_aligned(context):
    client, store = context
    site = store.create_site('North')
    _, sensor = enroll(store, site['id'])
    valid = network_scope(store)
    disabled = network_scope(store, '192.168.18.0/24', 'Disabled LAN')
    unconfirmed = network_scope(store, '192.168.19.0/24', 'Unconfirmed LAN')
    with get_connection(store.db_path) as connection:
        connection.execute('UPDATE authorized_scopes SET enabled=0 WHERE id=?', (disabled['id'],))
        connection.execute('UPDATE authorized_scopes SET authorized=0,authorization_confirmed_at=NULL,authorization_confirmation_version=NULL,authorization_source=NULL WHERE id=?', (unconfirmed['id'],))
    other_site = store.create_site('South')
    _, other_sensor = enroll(store, other_site['id'], 'Other sensor')
    bound_elsewhere = network_scope(store, '172.16.8.0/24', 'South LAN')
    store.assign_scope(other_sensor.record['id'], bound_elsewhere['id'])

    response = client.get(f"/sites/{site['id']}/eligible-sensor-scopes?sensor_id={sensor.record['id']}&limit=1&offset=0")
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    page = response.json()
    assert page['limit'] == 1 and page['offset'] == 0 and page['has_more'] is False
    second = client.get(f"/sites/{site['id']}/eligible-sensor-scopes?sensor_id={sensor.record['id']}&limit=1&offset=1").json()
    returned = page['items'] + second['items']
    assert [row['id'] for row in returned] == [valid['id']]
    assert all(row['scope_type'] == 'PRIVATE_NETWORK' for row in returned)
    ids = {row['id'] for row in client.get(f"/sites/{site['id']}/eligible-sensor-scopes?sensor_id={sensor.record['id']}").json()['items']}
    assert disabled['id'] not in ids
    assert unconfirmed['id'] not in ids
    assert bound_elsewhere['id'] not in ids
    assert client.get(f"/sites/{other_site['id']}/eligible-sensor-scopes?sensor_id={sensor.record['id']}").status_code == 400
    assert client.get(f"/sites/999/eligible-sensor-scopes?sensor_id={sensor.record['id']}").status_code == 404
    assert client.get(f"/sites/{site['id']}/eligible-sensor-scopes?sensor_id={sensor.record['id']}&limit=101").status_code == 422
    assert client.get(f"/sites/{site['id']}/eligible-sensor-scopes?sensor_id={sensor.record['id']}&offset=100001").status_code == 422


def test_management_mutations_keep_existing_lifecycle_and_assignment_semantics(context):
    client, store = context
    site = client.post('/sites', json={'name': 'West', 'description': 'sensor site', 'enabled': True})
    assert site.status_code == 201
    site = site.json()
    assert client.get('/sites').json() == [site]
    assert client.get(f"/sites/{site['id']}").json() == site

    issued_response = client.post(f"/sites/{site['id']}/sensor-enrollments", json={'ttl_seconds': 300})
    assert issued_response.status_code == 201
    issued = issued_response.json()
    assert issued['token']
    assert issued['expires_at']
    with get_connection(store.db_path) as connection:
        stored = connection.execute('SELECT token_hash FROM sensor_enrollment_tokens WHERE id=?', (issued['id'],)).fetchone()[0]
        assert stored != issued['token']
    listed = client.get(f"/sites/{site['id']}/sensor-enrollments").json()
    assert listed[0]['id'] == issued['id']
    assert not {'token', 'token_hash'} & listed[0].keys()

    # A later issuance does not invalidate an earlier outstanding invitation.
    second = client.post(f"/sites/{site['id']}/sensor-enrollments", json={}).json()
    registered = store.consume_enrollment(issued['token'], name='West sensor', platform='linux', version='2')
    sensor_id = registered.record['id']
    assert client.get(f"/sites/{site['id']}/sensor-enrollments").json()[0]['consumed_at']
    assert client.patch(f'/sensors/{sensor_id}', json={'enabled': False}).json()['enabled'] is False
    assert client.patch(f'/sensors/{sensor_id}', json={'enabled': True}).json()['enabled'] is True

    assigned_scope = network_scope(store)
    path = f'/sensors/{sensor_id}/scope-assignments'
    added = client.post(path, json={'scope_id': assigned_scope['id']})
    assert added.status_code == 200
    assignment_rows = client.get(path).json()
    assert assignment_rows == [added.json()]
    assert assignment_rows[0]['scope_name'] == 'Office LAN'
    assert assignment_rows[0]['scope_type'] == 'PRIVATE_NETWORK'
    assert assignment_rows[0]['scope_enabled'] is True
    assert client.post(path, json={'scope_id': assigned_scope['id']}).json() == added.json()
    revoked = client.delete(f'/sensors/{sensor_id}/credential')
    assert revoked.status_code == 200
    assert revoked.json()['status'] == 'DISABLED'  # legacy sensor detail status remains unchanged
    assert client.get('/sensors?status=REVOKED').json()['items'][0]['status'] == 'REVOKED'
    assert client.get(path).json() == assignment_rows
    assert client.patch(f'/sensors/{sensor_id}', json={'enabled': True}).status_code == 400
    with pytest.raises(RemoteSensorAuthError):
        store.heartbeat(sensor_id, registered.secret, platform='linux', version='2')
    assert client.delete(f'{path}/{assigned_scope["id"]}').status_code == 204
    assert client.delete(f'{path}/{assigned_scope["id"]}').status_code == 204
    assert client.delete(f'/sensor-enrollments/{second["id"]}').status_code == 200

    site_disabled = client.patch(f"/sites/{site['id']}", json={'enabled': False})
    assert site_disabled.json()['enabled'] is False
    assert client.post(f"/sites/{site['id']}/sensor-enrollments", json={}).status_code == 400
    assert client.patch(f"/sites/{site['id']}", json={'enabled': True}).json()['enabled'] is True


def test_secret_fields_absent_from_non_issuance_responses_and_errors(context):
    client, store = context
    site = store.create_site('Secret boundary')
    issued = client.post(f"/sites/{site['id']}/sensor-enrollments", json={}).json()
    registered = store.consume_enrollment(issued['token'], name='Secret sensor', platform='linux', version='1')
    scope = network_scope(store)
    assignment_path = f"/sensors/{registered.record['id']}/scope-assignments"
    assignment = client.post(assignment_path, json={'scope_id': scope['id']}).json()
    responses = [
        client.get('/sites').json(), client.get(f"/sites/{site['id']}").json(),
        client.get(f"/sites/{site['id']}/sensor-enrollments").json(),
        client.get('/sensors').json(), client.get(f"/sensors/{registered.record['id']}").json(),
        client.get(assignment_path).json(), assignment,
        client.get(f"/sites/{site['id']}/eligible-sensor-scopes?sensor_id={registered.record['id']}").json(),
    ]
    for response in responses:
        serialized = json.dumps(response)
        for forbidden in ('token_hash', 'credential_hash', 'credential_salt', 'credential_iterations', issued['token'], registered.secret):
            assert forbidden not in serialized
    error = client.post(assignment_path, json={'scope_id': 999999}).text
    assert issued['token'] not in error and registered.secret not in error


def test_eligible_scope_route_is_registered_with_shared_local_management_dependency():
    route = next(route for route in api.app.routes
                 if getattr(route, 'path', None) == '/sites/{site_id}/eligible-sensor-scopes')
    assert any(dependency.dependency is local_management for dependency in route.dependencies)


def test_eligible_scope_route_handler_returns_projection_and_maps_missing_site(tmp_path, monkeypatch):
    path = tmp_path / 'eligible-route.db'
    monkeypatch.setattr(api, 'DB_PATH', path)
    store = RemoteSensorStore(path)
    site = store.create_site('Route site')
    _, sensor = enroll(store, site['id'])
    target_scope = network_scope(store)
    route = next(route for route in api.app.routes
                 if getattr(route, 'path', None) == '/sites/{site_id}/eligible-sensor-scopes')
    payload = route.endpoint(site['id'], sensor.record['id'], limit=100, offset=0)
    assert payload['items'][0]['id'] == target_scope['id']
    with pytest.raises(api.HTTPException) as exc:
        route.endpoint(999, sensor.record['id'], limit=100, offset=0)
    assert exc.value.status_code == 404
