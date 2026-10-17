from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from api.remote_sensors import operator_task_creation_projection
from database.db import get_connection, initialize_database
from database.migrations import MIGRATIONS
from database.inventory import create_device
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.remote_tasks import MAX_ACTIVE_TASKS_PER_SENSOR, RemoteTaskError, RemoteTaskStore
from database.scopes import get_scope_for_network


NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


@pytest.fixture
def task_context(tmp_path):
    path = tmp_path / 'task-operations.db'
    store = RemoteSensorStore(path, clock=lambda: NOW)
    site = store.create_site('Operations site')
    invitation = store.create_enrollment(site['id'])
    sensor = store.consume_enrollment(invitation.secret, name='Sensor A', platform='linux', version='1',
        reported_capabilities=['HOST_DISCOVERY', 'SERVICE_DISCOVERY'])
    network = create_network('192.168.20.0/24', 'Operations LAN', '', True, True, path)
    scope = get_scope_for_network(network['id'], path)
    store.assign_scope(sensor.record['id'], scope['id'])
    device = create_device(stable_key='operations-device', network_id=network['id'],
        mac_address=None, hostname=None, vendor=None, first_seen=NOW.isoformat(), last_seen=NOW.isoformat(),
        last_ip_address='192.168.20.14', status='ONLINE', identity_confidence='LOW', db_path=path)
    return {'path': path, 'store': store, 'tasks': RemoteTaskStore(store), 'site': site,
            'sensor': sensor.record, 'scope': scope, 'network': network, 'device': device}


def test_safe_operator_task_projection_excludes_internal_row_fields():
    internal = {
        'id': 'task-id', 'sensor_id': 1, 'site_id': 2, 'scope_id': 3,
        'task_type': 'DISCOVER_NETWORK', 'status': 'PENDING', 'target_device_id': None,
        'target_ip': None, 'created_at': NOW.isoformat(),
        'expires_at': (NOW + timedelta(seconds=900)).isoformat(), 'attempt_count': 0,
        'result_digest': 'digest', 'created_by_source': 'local_management',
        'error_code': None, 'error_message': None, 'arbitrary_payload': {'command': 'x'},
    }
    projected = operator_task_creation_projection(internal)
    assert projected == {key: internal[key] for key in (
        'id', 'sensor_id', 'site_id', 'scope_id', 'task_type', 'status',
        'target_device_id', 'target_ip', 'created_at', 'expires_at', 'attempt_count',
    )}
    assert projected['status'] == 'PENDING'


def test_task_selector_projections_are_bounded_and_capability_aware(task_context):
    ctx = task_context
    scopes = ctx['tasks'].list_eligible_task_scopes(ctx['sensor']['id'], limit=1, offset=0)
    assert scopes == {'items': [{
        'scope_id': ctx['scope']['id'], 'scope_name': 'Operations LAN',
        'canonical_target': '192.168.20.0/24',
        'supported_task_types': ['DISCOVER_NETWORK', 'DISCOVER_SERVICES'],
    }], 'limit': 1, 'offset': 0, 'has_more': False}
    devices = ctx['tasks'].list_eligible_task_devices(ctx['sensor']['id'], ctx['scope']['id'], limit=1)
    assert devices == {'items': [{'device_id': ctx['device']['id'],
        'scope_id': ctx['scope']['id'], 'ip_address': '192.168.20.14'}],
        'limit': 1, 'offset': 0, 'has_more': False}
    with get_connection(ctx['path']) as connection:
        connection.execute("UPDATE remote_sensors SET capabilities='[\"HOST_DISCOVERY\"]' WHERE id=?",
                           (ctx['sensor']['id'],))
    assert ctx['tasks'].list_eligible_task_scopes(ctx['sensor']['id'])['items'][0]['supported_task_types'] == ['DISCOVER_NETWORK']
    with pytest.raises(RemoteTaskError) as error:
        ctx['tasks'].list_eligible_task_devices(ctx['sensor']['id'], ctx['scope']['id'])
    assert error.value.code == 'CAPABILITY_NOT_ALLOWED'


def test_selector_projections_exclude_unassigned_disabled_or_out_of_scope_entities(task_context):
    ctx = task_context
    other_network = create_network('10.20.0.0/24', 'Other LAN', '', True, True, ctx['path'])
    other_scope = get_scope_for_network(other_network['id'], ctx['path'])
    assert other_scope['id'] not in {row['scope_id'] for row in ctx['tasks'].list_eligible_task_scopes(ctx['sensor']['id'])['items']}
    with get_connection(ctx['path']) as connection:
        connection.execute('UPDATE devices SET last_ip_address=? WHERE id=?', ('203.0.113.9', ctx['device']['id']))
    assert ctx['tasks'].list_eligible_task_devices(ctx['sensor']['id'], ctx['scope']['id'])['items'] == []
    with get_connection(ctx['path']) as connection:
        connection.execute('UPDATE networks SET enabled=0 WHERE id=?', (ctx['network']['id'],))
    assert ctx['tasks'].list_eligible_task_scopes(ctx['sensor']['id'])['items'] == []


def test_queue_cap_counts_only_unexpired_nonterminal_tasks_per_sensor(task_context):
    ctx = task_context
    tasks = ctx['tasks']
    sensor_id = ctx['sensor']['id']
    scope_id = ctx['scope']['id']
    device_id = ctx['device']['id']
    for index in range(MAX_ACTIVE_TASKS_PER_SENSOR - 1):
        task_type = 'DISCOVER_SERVICES' if index % 2 else 'DISCOVER_NETWORK'
        tasks.create_task(sensor_id, scope_id, task_type,
                          device_id=device_id if task_type == 'DISCOVER_SERVICES' else None)
    twentieth = tasks.create_task(sensor_id, scope_id, 'DISCOVER_NETWORK')
    assert twentieth['status'] == 'PENDING'
    with pytest.raises(RemoteTaskError) as error:
        tasks.create_task(sensor_id, scope_id, 'DISCOVER_NETWORK')
    assert (error.value.code, error.value.status_code) == ('TASK_QUEUE_FULL', 409)

    other_invitation = ctx['store'].create_enrollment(ctx['site']['id'])
    other_sensor = ctx['store'].consume_enrollment(other_invitation.secret, name='Sensor B', platform='linux',
        version='1', reported_capabilities=['HOST_DISCOVERY'])
    ctx['store'].assign_scope(other_sensor.record['id'], scope_id)
    assert tasks.create_task(other_sensor.record['id'], scope_id, 'DISCOVER_NETWORK')['status'] == 'PENDING'

    with get_connection(ctx['path']) as connection:
        connection.execute("UPDATE remote_sensor_tasks SET status='COMPLETED' WHERE id=(SELECT id FROM remote_sensor_tasks WHERE sensor_id=? ORDER BY id LIMIT 1)",
                           (sensor_id,))
        connection.execute("UPDATE remote_sensor_tasks SET expires_at=? WHERE id=(SELECT id FROM remote_sensor_tasks WHERE sensor_id=? AND status='PENDING' ORDER BY id LIMIT 1)",
                           ((NOW - timedelta(seconds=1)).isoformat(), sensor_id))
    assert tasks.create_task(sensor_id, scope_id, 'DISCOVER_NETWORK')['status'] == 'PENDING'


def test_queue_cap_transaction_serializes_competing_creations(task_context):
    ctx = task_context
    for _ in range(MAX_ACTIVE_TASKS_PER_SENSOR - 1):
        ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')

    def attempt():
        try:
            ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
            return 'created'
        except RemoteTaskError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == ['TASK_QUEUE_FULL', 'created']
    with get_connection(ctx['path']) as connection:
        count = connection.execute("SELECT COUNT(*) FROM remote_sensor_tasks WHERE sensor_id=? AND status IN ('PENDING','CLAIMED','RUNNING') AND expires_at>?",
                                   (ctx['sensor']['id'], NOW.isoformat())).fetchone()[0]
    assert count == MAX_ACTIVE_TASKS_PER_SENSOR


def test_failed_queue_create_does_not_insert(task_context):
    ctx = task_context
    for _ in range(MAX_ACTIVE_TASKS_PER_SENSOR):
        ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
    with get_connection(ctx['path']) as connection:
        before = connection.execute('SELECT COUNT(*) FROM remote_sensor_tasks').fetchone()[0]
    with pytest.raises(RemoteTaskError):
        ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
    with get_connection(ctx['path']) as connection:
        after = connection.execute('SELECT COUNT(*) FROM remote_sensor_tasks').fetchone()[0]
    assert after == before


def test_task_operations_need_no_schema_migration(task_context):
    initialize_database(task_context['path'])
    with get_connection(task_context['path']) as connection:
        version = connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]
    assert version == 43
    assert max(version for version, _ in MIGRATIONS) == 43
