from datetime import datetime, timedelta, timezone

import pytest

from database.db import get_connection
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.remote_tasks import RemoteTaskError, RemoteTaskStore
from database.scopes import get_scope_for_network
from services.remote_sensor_models import Capability


@pytest.fixture
def task_history_context(tmp_path):
    clock = [datetime(2026, 10, 17, tzinfo=timezone.utc)]
    path = tmp_path / 'task-history.db'
    sensors = RemoteSensorStore(path, clock=lambda: clock[0])
    site = sensors.create_site('History Site')
    enrollment = sensors.create_enrollment(site['id'])
    sensor = sensors.consume_enrollment(
        enrollment.secret, name='History Sensor', platform='declared', version='1',
        reported_capabilities=[Capability.HOST_DISCOVERY.value],
    ).record
    network = create_network('192.168.80.0/24', 'History LAN', '', True, True, path)
    scope = get_scope_for_network(network['id'], path)
    sensors.assign_scope(sensor['id'], scope['id'])
    tasks = RemoteTaskStore(sensors)
    return {'clock': clock, 'path': path, 'sensors': sensors, 'sensor': sensor,
            'site': site, 'scope': scope, 'tasks': tasks}


def test_task_history_projection_is_safe_bounded_and_derived(task_history_context):
    ctx = task_history_context
    task = ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
    with get_connection(ctx['path']) as connection:
        connection.execute("""UPDATE remote_sensor_tasks SET status='FAILED', error_code=?, error_message=?,
            result_digest=?, created_by_source=?, expires_at=?, failed_at=? WHERE id=?""",
            ('SCANNER_TIMEOUT', 'raw scanner trace', 'private digest', 'local_management',
             (ctx['clock'][0] - timedelta(seconds=1)).isoformat(), ctx['clock'][0].isoformat(), task['id']))
    result = ctx['tasks'].list_task_history(limit=1)
    row = result['items'][0]
    assert result['has_more'] is False and result['limit'] == 1
    assert row['status'] == 'FAILED' and row['expired'] is False
    assert row['failure_code'] == 'SCANNER_TIMEOUT'
    assert row['failure_message_safe'] == 'Sensor scanner timed out.'
    assert row['sensor_name'] == 'History Sensor' and row['site_name'] == 'History Site'
    assert row['canonical_target'] == '192.168.80.0/24'
    assert set(row) == {
        'id', 'sensor_id', 'sensor_name', 'site_id', 'site_name', 'scope_id', 'scope_name',
        'canonical_target', 'target_device_id', 'target_ip', 'task_type', 'status', 'created_at',
        'expires_at', 'claimed_at', 'started_at', 'completed_at', 'failed_at', 'attempt_count',
        'failure_code', 'failure_message_safe', 'expired',
    }
    assert 'raw scanner trace' not in str(result)
    assert 'private digest' not in str(result)
    assert 'local_management' not in str(result)


def test_task_history_filters_order_and_bounded_time_range(task_history_context):
    ctx = task_history_context
    first = ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
    second_time = ctx['clock'][0] + timedelta(seconds=1)
    with get_connection(ctx['path']) as connection:
        connection.execute('UPDATE remote_sensor_tasks SET created_at=? WHERE id=?', (second_time.isoformat(), first['id']))
    second = ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
    result = ctx['tasks'].list_task_history(
        limit=1, sensor_id=ctx['sensor']['id'], site_id=ctx['site']['id'],
        scope_id=ctx['scope']['id'], task_type='DISCOVER_NETWORK', status='PENDING',
        created_after=ctx['clock'][0] - timedelta(days=1),
        created_before=ctx['clock'][0] + timedelta(days=1),
    )
    assert result['items'][0]['id'] == first['id']
    assert result['has_more'] is True
    assert ctx['tasks'].list_task_history(device_id=1)['items'] == []
    with pytest.raises(RemoteTaskError, match='both creation time bounds'):
        ctx['tasks'].list_task_history(created_after=ctx['clock'][0])
    with pytest.raises(RemoteTaskError, match='timezone-aware'):
        ctx['tasks'].list_task_history(created_after=datetime(2026, 10, 16), created_before=ctx['clock'][0])
    with pytest.raises(RemoteTaskError, match='no longer than 90 days'):
        ctx['tasks'].list_task_history(
            created_after=ctx['clock'][0], created_before=ctx['clock'][0] + timedelta(days=91))
    assert second['id'] != first['id']


def test_task_history_never_mutates_rows_and_maps_unknown_failure_codes(task_history_context):
    ctx = task_history_context
    task = ctx['tasks'].create_task(ctx['sensor']['id'], ctx['scope']['id'], 'DISCOVER_NETWORK')
    with get_connection(ctx['path']) as connection:
        connection.execute("""UPDATE remote_sensor_tasks SET status='FAILED',error_code=?,error_message=?,
            expires_at=? WHERE id=?""",
            ('UNEXPECTED_SECRET_CODE', 'raw message', (ctx['clock'][0] - timedelta(seconds=1)).isoformat(), task['id']))
        before = connection.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task['id'],)).fetchone()
    result = ctx['tasks'].list_task_history()
    assert result['items'][0]['failure_code'] == 'UNKNOWN_FAILURE'
    assert result['items'][0]['failure_message_safe'] == 'Unknown task failure.'
    assert result['items'][0]['expired'] is False
    with get_connection(ctx['path']) as connection:
        after = connection.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task['id'],)).fetchone()
    assert before == after
