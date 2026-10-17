from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request

from api.remote_sensors import local_management, register_remote_routes
from database.db import get_connection
from database.networks import create_network
from database.scopes import get_scope_for_network
from database.remote_sensors import RemoteSensorStore


@pytest.fixture
def fleet(tmp_path):
    now = [datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)]
    store = RemoteSensorStore(tmp_path / 'fleet.db', clock=lambda: now[0])
    site = store.create_site('Office')
    return store, site, now


def make_sensor(store, site, *, name='Sensor', platform='linux', caps=()):
    token = store.create_enrollment(site['id'])
    return store.consume_enrollment(token.secret, name=name, platform=platform, version='1.2',
                                    reported_capabilities=list(caps))


def test_fleet_inventory_is_bounded_joined_and_deterministically_paginated(fleet):
    store, site, now = fleet
    other_site = store.create_site('Warehouse')
    first = make_sensor(store, site, name='zeta', caps=['SERVICE_DISCOVERY', 'HOST_DISCOVERY'])
    second = make_sensor(store, site, name='Alpha')
    third = make_sensor(store, other_site, name='beta')
    network = create_network('192.168.1.0/24', 'LAN', '', True, True, store.db_path)
    scope = get_scope_for_network(network['id'], store.db_path)
    store.assign_scope(first.record['id'], scope['id'])

    page = store.list_fleet_sensors(limit=2, offset=0)
    assert page['evaluated_at'] == now[0].isoformat()
    assert page['limit'] == 2 and page['offset'] == 0 and page['has_more'] is True
    assert [item['name'] for item in page['items']] == ['Alpha', 'zeta']
    row = page['items'][1]
    assert (row['site_id'], row['site_name'], row['site_enabled']) == (site['id'], 'Office', True)
    assert row['platform'] == 'linux' and row['version'] == '1.2'
    assert row['registered_at'] and row['last_seen_at'] is None
    assert row['status'] == 'PENDING' and row['heartbeat_age_seconds'] is None
    assert row['capabilities'] == ['HOST_DISCOVERY', 'SERVICE_DISCOVERY']
    assert row['assignment_count'] == 1
    assert store.list_fleet_sensors(limit=2, offset=2)['items'][0]['id'] == third.record['id']
    assert store.list_fleet_sensors(limit=2, offset=2)['has_more'] is False


@pytest.mark.parametrize(('age', 'status'), [
    (timedelta(seconds=300), 'ONLINE'),
    (timedelta(seconds=300, microseconds=1), 'OFFLINE'),
    (timedelta(seconds=301), 'OFFLINE'),
])
def test_fleet_heartbeat_boundaries(fleet, age, status):
    store, site, now = fleet
    issued = make_sensor(store, site)
    with get_connection(store.db_path) as connection:
        connection.execute('UPDATE remote_sensors SET last_seen_at=? WHERE id=?',
                           ((now[0] - age).isoformat(), issued.record['id']))
    row = store.list_fleet_sensors()['items'][0]
    assert row['status'] == status
    assert row['heartbeat_age_seconds'] == (301 if age.total_seconds() > 300 else 300)


def test_fleet_status_precedence_and_single_clock(fleet):
    store, site, now = fleet
    revoked = make_sensor(store, site, name='revoked')
    disabled = make_sensor(store, site, name='disabled')
    live = make_sensor(store, site, name='live')
    store.revoke_sensor(revoked.record['id'])
    store.set_sensor_enabled(disabled.record['id'], False)
    for issued in (revoked, disabled, live):
        with get_connection(store.db_path) as connection:
            connection.execute('UPDATE remote_sensors SET last_seen_at=? WHERE id=?',
                               (now[0].isoformat(), issued.record['id']))
    now[0] += timedelta(seconds=1)
    statuses = {item['name']: item for item in store.list_fleet_sensors()['items']}
    assert statuses['revoked']['status'] == 'REVOKED'
    assert statuses['revoked']['heartbeat_age_seconds'] == 1
    assert statuses['disabled']['status'] == 'DISABLED'
    assert statuses['disabled']['heartbeat_age_seconds'] == 1
    assert statuses['live']['status'] == 'ONLINE'
    assert statuses['live']['heartbeat_age_seconds'] == 1

    store.set_site_enabled(site['id'], False)
    disabled_site_statuses = {item['name']: item['status'] for item in store.list_fleet_sensors()['items']}
    assert disabled_site_statuses == {'revoked': 'REVOKED', 'disabled': 'DISABLED', 'live': 'DISABLED'}
    disabled_site_rows = {item['name']: item for item in store.list_fleet_sensors()['items']}
    assert disabled_site_rows['live']['heartbeat_age_seconds'] == 1


def test_fleet_unknown_and_malformed_capabilities_fail_safely(fleet):
    store, site, now = fleet
    future = make_sensor(store, site, name='future')
    malformed = make_sensor(store, site, name='malformed')
    bad_caps = make_sensor(store, site, name='bad-caps')
    with get_connection(store.db_path) as connection:
        connection.execute('UPDATE remote_sensors SET last_seen_at=? WHERE id=?',
                           ((now[0] + timedelta(seconds=1)).isoformat(), future.record['id']))
        connection.execute('UPDATE remote_sensors SET last_seen_at=? WHERE id=?',
                           ('not-a-timestamp', malformed.record['id']))
        connection.execute('UPDATE remote_sensors SET capabilities=? WHERE id=?',
                           ('{"unexpected":"metadata"}', bad_caps.record['id']))
    items = {item['name']: item for item in store.list_fleet_sensors()['items']}
    assert items['future']['status'] == 'UNKNOWN' and items['future']['heartbeat_age_seconds'] is None
    assert items['malformed']['status'] == 'UNKNOWN' and items['malformed']['heartbeat_age_seconds'] is None
    assert items['bad-caps']['capabilities'] is None
    empty = make_sensor(store, site, name='empty-caps')
    assert {item['name']: item for item in store.list_fleet_sensors()['items']}['empty-caps']['capabilities'] == []


def test_fleet_missing_historical_site_is_retained_as_unknown(fleet):
    store, site, now = fleet
    issued = make_sensor(store, site)
    with get_connection(store.db_path) as connection:
        connection.execute('PRAGMA foreign_keys=OFF')
        connection.execute('DELETE FROM sites WHERE id=?', (site['id'],))
        connection.execute('UPDATE remote_sensors SET last_seen_at=? WHERE id=?',
                           (now[0].isoformat(), issued.record['id']))
    row = store.list_fleet_sensors()['items'][0]
    assert row['site_id'] == site['id'] and row['site_name'] is None and row['site_enabled'] is None
    assert row['status'] == 'UNKNOWN'


def test_fleet_filters_unknown_site_and_secret_projection(fleet):
    store, site, _ = fleet
    issued = make_sensor(store, site, name='Alpha', caps=['HOST_DISCOVERY'])
    another = make_sensor(store, store.create_site('Other'), name='Beta', platform='windows')
    disabled = make_sensor(store, site, name='Disabled')
    store.set_sensor_enabled(disabled.record['id'], False)
    with get_connection(store.db_path) as connection:
        connection.execute('UPDATE remote_sensors SET last_seen_at=? WHERE id=?',
                           (store._now().isoformat(), issued.record['id']))
    assert [item['id'] for item in store.list_fleet_sensors(site_id=site['id'])['items']] == [issued.record['id'], disabled.record['id']]
    assert [item['id'] for item in store.list_fleet_sensors(status='ONLINE')['items']] == [issued.record['id']]
    assert [item['id'] for item in store.list_fleet_sensors(platform='windows')['items']] == [another.record['id']]
    assert [item['id'] for item in store.list_fleet_sensors(enabled=True)['items']] == [issued.record['id'], another.record['id']]
    assert [item['id'] for item in store.list_fleet_sensors(enabled=False)['items']] == [disabled.record['id']]
    with pytest.raises(LookupError):
        store.list_fleet_sensors(site_id=999)
    payload = json.dumps(store.list_fleet_sensors())
    row = store.list_fleet_sensors()['items'][0]
    assert set(row) == {'id', 'sensor_uuid', 'name', 'site_id', 'site_name', 'site_enabled',
        'platform', 'version', 'enabled', 'registered_at', 'last_seen_at', 'status',
        'heartbeat_age_seconds', 'capabilities', 'assignment_count'}
    forbidden_keys = {'credential_salt', 'credential_hash', 'credential_iterations',
                      'credential_revoked_at', 'token_hash', 'token', 'secret', 'raw_result'}
    assert forbidden_keys.isdisjoint(row)
    assert issued.secret not in payload and another.secret not in payload


@pytest.mark.parametrize(('kwargs', 'message'), [
    ({'limit': 0}, 'pagination'), ({'limit': 101}, 'pagination'),
    ({'offset': -1}, 'pagination'), ({'offset': 100001}, 'pagination'),
    ({'status': 'HEALTHY'}, 'status'),
])
def test_fleet_rejects_invalid_query_values(fleet, kwargs, message):
    store, _, _ = fleet
    with pytest.raises(ValueError, match=message):
        store.list_fleet_sensors(**kwargs)


def test_fleet_read_is_read_only_and_schema_stays_43(fleet):
    store, site, _ = fleet
    issued = make_sensor(store, site)
    with get_connection(store.db_path) as connection:
        before = tuple(connection.execute('SELECT enabled, credential_hash, updated_at FROM remote_sensors WHERE id=?',
                                          (issued.record['id'],)).fetchone())
        schema = connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]
        related_before = tuple(connection.execute(
            'SELECT (SELECT COUNT(*) FROM sites), (SELECT COUNT(*) FROM sensor_scope_assignments), '
            '(SELECT COUNT(*) FROM remote_sensor_tasks)'
        ).fetchone())
    store.list_fleet_sensors()
    with get_connection(store.db_path) as connection:
        after = tuple(connection.execute('SELECT enabled, credential_hash, updated_at FROM remote_sensors WHERE id=?',
                                         (issued.record['id'],)).fetchone())
        related_after = tuple(connection.execute(
            'SELECT (SELECT COUNT(*) FROM sites), (SELECT COUNT(*) FROM sensor_scope_assignments), '
            '(SELECT COUNT(*) FROM remote_sensor_tasks)'
        ).fetchone())
    assert after == before
    assert related_after == related_before
    assert schema == 43


def test_fleet_route_contract_reuses_management_guard_and_maps_site_not_found(fleet):
    store, site, _ = fleet
    issued = make_sensor(store, site)
    app = FastAPI()
    register_remote_routes(app, lambda: store)
    route = next(route for route in app.routes if getattr(route, 'path', None) == '/sensors')
    assert route.methods == {'GET'}
    assert any(dependency.call is local_management for dependency in route.dependant.dependencies)
    response = route.endpoint(limit=10, offset=0, site_id=site['id'], status='PENDING',
                              platform='linux', enabled='true')
    assert response['items'][0]['id'] == issued.record['id']
    with pytest.raises(HTTPException) as error:
        route.endpoint(limit=10, offset=0, site_id=999, status=None, platform=None, enabled=None)
    assert error.value.status_code == 404


@pytest.mark.parametrize('header', [
    (b'authorization', b'Bearer token'),
    (b'x-sensor-uuid', b'00000000-0000-0000-0000-000000000000'),
    (b'x-sentinelip-sensor-id', b'1'),
    (b'x-sentinelip-sensor-token', b'token'),
    (b'forwarded', b'for=127.0.0.1'),
    (b'x-forwarded-for', b'127.0.0.1'),
    (b'x-forwarded-host', b'localhost'),
    (b'origin', b'https://untrusted.example'),
])
def test_fleet_management_guard_rejects_sensor_and_forwarded_headers(header):
    request = Request({
        'type': 'http', 'method': 'GET', 'path': '/sensors', 'query_string': b'',
        'headers': [header], 'client': ('127.0.0.1', 5050),
        'server': ('127.0.0.1', 8000), 'scheme': 'http', 'http_version': '1.1',
    })
    with pytest.raises(HTTPException) as error:
        local_management(request, Response())
    assert error.value.status_code == 403


def test_fleet_management_guard_allows_direct_local_origin_and_sets_no_store():
    request = Request({
        'type': 'http', 'method': 'GET', 'path': '/sensors', 'query_string': b'',
        'headers': [(b'origin', b'http://localhost:5173')],
        'client': ('127.0.0.1', 5050), 'server': ('127.0.0.1', 8000),
        'scheme': 'http', 'http_version': '1.1',
    })
    response = Response()
    local_management(request, response)
    assert response.headers['cache-control'] == 'no-store'
