from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.remote_sensors import register_remote_routes
from api.remote_tasks import register_remote_task_routes
from api.sensor_enrollment import SensorBodyLimitMiddleware, register_machine_routes
from database.db import get_connection, initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.remote_tasks import RemoteTaskError, RemoteTaskStore
from database.scopes import get_scope_for_network, create_scope
from services.remote_sensor_executor import LinuxRemoteSensorExecutor, task_context_from_claim
from services.remote_sensor_models import (
    Capability, LocalExecutorGrant, RemoteSensorError, RemoteTaskContext,
    validate_remote_task,
)
from services.sensor_transport import authenticated_sensor_headers
from services.scan_models import HostDiscoveryResult, ScanResult
from services.service_models import PortObservation, ServiceDiscoveryResult, ServiceObservation

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


@pytest.fixture
def context(tmp_path):
    clock = [NOW]
    path = tmp_path / 'tasks.db'
    store = RemoteSensorStore(path, clock=lambda: clock[0])
    site = store.create_site('Home')
    enrollment = store.create_enrollment(site['id'])
    issued = store.consume_enrollment(enrollment.secret, name='Sensor A', platform='linux', version='1',
                                      reported_capabilities=[Capability.HOST_DISCOVERY.value,
                                                             Capability.SERVICE_DISCOVERY.value])
    network = create_network('192.168.1.0/24', 'Home LAN', '', True, True, path)
    scope = get_scope_for_network(network['id'], path)
    store.assign_scope(issued.record['id'], scope['id'])
    device = create_device(stable_key=f"network:{network['id']}:ip:192.168.1.20",
                           network_id=network['id'], mac_address=None, hostname='host', vendor=None,
                           first_seen=NOW.isoformat(), last_seen=NOW.isoformat(),
                           last_ip_address='192.168.1.20', status='ONLINE', identity_confidence='LOW',
                           db_path=path)
    app = FastAPI()
    register_remote_routes(app, lambda: store)
    register_machine_routes(app, lambda: store)
    register_remote_task_routes(app, lambda: store)
    app.add_middleware(SensorBodyLimitMiddleware)
    with TestClient(app, base_url='https://core.test', client=('192.168.1.9', 6000)) as machine:
        with TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 6001)) as admin:
            yield {'store': store, 'clock': clock, 'site': site, 'sensor': issued,
                   'network': network, 'scope': scope, 'device': device,
                   'machine': machine, 'admin': admin, 'path': path}


def headers(context, sensor=None):
    sensor = sensor or context['sensor']
    return authenticated_sensor_headers(sensor.record['sensor_uuid'], sensor.secret, now=context['clock'][0])


def create_network_task(context, sensor=None, scope=None):
    sensor = sensor or context['sensor'].record
    scope = scope or context['scope']
    return RemoteTaskStore(context['store']).create_task(sensor['id'], scope['id'], 'DISCOVER_NETWORK')


def claim(context, sensor=None):
    response = context['machine'].post('/sensor/tasks/claim', headers=headers(context, sensor))
    return response


def advance_nonce_headers(context, sensor=None):
    return headers(context, sensor)


def test_creation_and_target_derivation(context):
    store, scope, sensor, device = context['store'], context['scope'], context['sensor'].record, context['device']
    network_task = RemoteTaskStore(store).create_task(sensor['id'], scope['id'], 'DISCOVER_NETWORK')
    assert network_task['task_type'] == 'DISCOVER_NETWORK'
    assert network_task['status'] == 'PENDING'
    assert network_task['target_device_id'] is None and network_task['target_ip'] is None
    service_task = RemoteTaskStore(store).create_task(sensor['id'], scope['id'], 'DISCOVER_SERVICES', device_id=device['id'])
    assert service_task['target_device_id'] == device['id']
    assert service_task['target_ip'] == '192.168.1.20'
    assert service_task['expires_at'] == (context['clock'][0] + timedelta(minutes=15)).isoformat()
    with get_connection(store.db_path) as c:
        row = c.execute('SELECT task_type,result_digest FROM remote_sensor_tasks WHERE id=?',
                        (network_task['id'],)).fetchone()
        assert row == ('DISCOVER_NETWORK', None)
        assert {row[2] for row in c.execute('PRAGMA foreign_key_list(remote_sensor_tasks)')} >= {
            'remote_sensors', 'authorized_scopes', 'devices'}


@pytest.mark.parametrize('extra', ['target', 'ip_address', 'command', 'shell', 'nmap_flags', 'scope_cidr'])
def test_management_task_creation_rejects_arbitrary_fields(context, extra):
    admin, sensor, scope = context['admin'], context['sensor'].record, context['scope']
    response = admin.post(f"/sensors/{sensor['id']}/tasks/discover-network",
                          json={'scope_id': scope['id'], extra: '8.8.8.8'})
    assert response.status_code == 422


def test_creation_rejects_unassigned_disabled_capability_and_wrong_target(context):
    store, scope, sensor, device = context['store'], context['scope'], context['sensor'].record, context['device']
    store.remove_assignment(sensor['id'], scope['id'])
    with pytest.raises(RemoteTaskError) as exc:
        create_network_task(context)
    assert exc.value.code == 'SCOPE_NOT_ASSIGNED'
    store.assign_scope(sensor['id'], scope['id'])
    with get_connection(store.db_path) as c:
        c.execute('UPDATE remote_sensors SET capabilities=? WHERE id=?', ('[]', sensor['id']))
    with pytest.raises(RemoteTaskError) as exc:
        create_network_task(context)
    assert exc.value.code == 'CAPABILITY_NOT_ALLOWED'
    with get_connection(store.db_path) as c:
        c.execute("UPDATE remote_sensors SET capabilities='[\"SERVICE_DISCOVERY\"]' WHERE id=?", (sensor['id'],))
    with pytest.raises(RemoteTaskError) as exc:
        create_network_task(context)
    assert exc.value.code == 'CAPABILITY_NOT_ALLOWED'
    with get_connection(store.db_path) as c:
        c.execute('UPDATE devices SET last_ip_address=? WHERE id=?', ('8.8.8.8', device['id']))
    with pytest.raises(RemoteTaskError) as exc:
        RemoteTaskStore(store).create_task(sensor['id'], scope['id'], 'DISCOVER_SERVICES', device_id=device['id'])
    assert exc.value.code == 'TARGET_OUTSIDE_SCOPE'


def test_creation_rejects_public_unconfirmed_disabled_and_foreign_sensor(context):
    store, scope, sensor = context['store'], context['scope'], context['sensor'].record
    for kind, target in [('PUBLIC_IPV4', '8.8.8.8'), ('HOSTNAME', 'example.test'), ('PUBLIC_CIDR', '8.8.8.0/29')]:
        public = create_scope(scope_type=kind, canonical_target=target, authorized=True, enabled=True,
                              authorization_confirmed_at='fixture', authorization_confirmation_version='fixture',
                              authorization_source='fixture', db_path=store.db_path)
        with pytest.raises(RemoteTaskError):
            RemoteTaskStore(store).create_task(sensor['id'], public['id'], 'DISCOVER_NETWORK')
    with get_connection(store.db_path) as c:
        c.execute("UPDATE authorized_scopes SET authorized=0,enabled=0 WHERE id=?", (scope['id'],))
    with pytest.raises(RemoteTaskError):
        create_network_task(context)


def test_task_claim_owner_atomic_state_and_expiry(context):
    store, machine, issued = context['store'], context['machine'], context['sensor']
    task = create_network_task(context)
    response = claim(context)
    assert response.status_code == 200
    claimed = response.json()['task']
    assert claimed['id'] == task['id'] and claimed['status'] == 'CLAIMED'
    assert claimed['scope_cidr'] == '192.168.1.0/24'
    assert claimed['target_ip'] is None
    context_from_claim = task_context_from_claim(claimed)
    grant = LocalExecutorGrant(issued.record['sensor_uuid'], context['scope']['id'],
                               '192.168.1.0/24', frozenset({'HOST_DISCOVERY'}))
    assert validate_remote_task(context_from_claim, grant) is None
    with pytest.raises(RemoteSensorError):
        task_context_from_claim({**claimed, 'command': 'anything'})
    assert claim(context).json() == {'task': None}
    assert machine.post(f"/sensor/tasks/{task['id']}/start", headers=headers(context)).status_code == 200
    assert machine.post(f"/sensor/tasks/{task['id']}/start", headers=headers(context)).status_code == 409
    task2 = create_network_task(context)
    RemoteTaskStore(store).transition(issued.record['id'], task2['id'], 'cancel')
    other = store.create_site('Other')
    other_token = store.create_enrollment(other['id'])
    other_sensor = store.consume_enrollment(other_token.secret, name='B', platform='linux', version='1',
                                            reported_capabilities=['HOST_DISCOVERY'])
    assert claim(context, other_sensor).json() == {'task': None}
    expiry_task = RemoteTaskStore(store).create_task(issued.record['id'], context['scope']['id'],
                                                       'DISCOVER_NETWORK', ttl_seconds=60)
    context['clock'][0] += timedelta(seconds=60)
    assert claim(context).json() == {'task': None}
    with get_connection(store.db_path) as c:
        row = c.execute('SELECT status,error_code FROM remote_sensor_tasks WHERE id=?', (expiry_task['id'],)).fetchone()
        assert row == ('FAILED', 'TASK_EXPIRED')
        assert c.execute('SELECT status FROM remote_sensor_tasks WHERE id=?', (task2['id'],)).fetchone()[0] == 'CANCELLED'


def test_machine_transport_replay_and_disabled_sensor(context):
    task = create_network_task(context)
    h = headers(context)
    assert context['machine'].post('/sensor/tasks/claim', headers=h).status_code == 200
    assert context['machine'].post('/sensor/tasks/claim', headers=h).status_code == 409
    context['store'].set_sensor_enabled(context['sensor'].record['id'], False)
    assert context['machine'].post('/sensor/tasks/claim', headers=headers(context)).status_code == 401


def test_local_grant_validation_and_executor_is_typed(context):
    from datetime import datetime
    from services.service_models import ServiceDiscoveryResult
    class FakeHosts:
        def __init__(self): self.targets=[]
        def discover_hosts(self, cidr):
            self.targets.append(cidr)
            host=HostDiscoveryResult('192.168.1.25', discovered_at=datetime.now(), source='nmap')
            return ScanResult(cidr,'nmap',datetime.now(),datetime.now(),(host,))
    class FakeServices:
        def __init__(self): self.targets=[]
        def discover_services(self, target):
            self.targets.append(target)
            return ServiceDiscoveryResult(target,'nmap',datetime.now(),datetime.now(),
                 (PortObservation(target,22,'tcp','open',datetime.now(),'nmap'),),())
    task = RemoteTaskContext('task', context['sensor'].record['sensor_uuid'], context['scope']['id'],
                             'PRIVATE_NETWORK','DISCOVER_NETWORK','192.168.1.0/24',None,
                             context['network']['id'])
    grant = LocalExecutorGrant(task.sensor_uuid, task.scope_id, '192.168.1.0/24',
                               frozenset({'HOST_DISCOVERY','SERVICE_DISCOVERY'}))
    assert validate_remote_task(task, grant) is None
    hosts, services = FakeHosts(), FakeServices()
    executor = LinuxRemoteSensorExecutor(hosts, services)
    assert executor.discover_network(task, grant).hosts[0].ip_address == '192.168.1.25'
    assert hosts.targets == ['192.168.1.0/24']
    service_task = RemoteTaskContext('task2', task.sensor_uuid, task.scope_id, 'PRIVATE_NETWORK',
                                     'DISCOVER_SERVICES','192.168.1.0/24','192.168.1.20',
                                     context['network']['id'],context['device']['id'])
    assert executor.discover_services(service_task, grant).target_ip == '192.168.1.20'
    assert services.targets == ['192.168.1.20']
    malicious = RemoteTaskContext('bad', task.sensor_uuid, task.scope_id, 'PRIVATE_NETWORK',
                                  'DISCOVER_SERVICES','192.168.1.0/24','8.8.8.8',
                                  context['network']['id'],context['device']['id'])
    with pytest.raises(RemoteSensorError): executor.discover_services(malicious, grant)
    assert services.targets == ['192.168.1.20']
    for changed in [RemoteTaskContext('bad',task.sensor_uuid,task.scope_id,'PUBLIC_IPV4','DISCOVER_NETWORK',task.scope_cidr),
                    RemoteTaskContext('bad',task.sensor_uuid,task.scope_id,'PRIVATE_NETWORK','EXEC',task.scope_cidr),
                    RemoteTaskContext('bad',task.sensor_uuid,task.scope_id,'PRIVATE_NETWORK','DISCOVER_NETWORK','192.168.2.0/24')]:
        with pytest.raises(RemoteSensorError): validate_remote_task(changed,grant)


def test_claimed_result_ingestion_inventory_provenance_and_retry(context):
    machine, admin, sensor, scope = context['machine'], context['admin'], context['sensor'], context['scope']
    created = admin.post(f"/sensors/{sensor.record['id']}/tasks/discover-network", json={'scope_id': scope['id']})
    assert created.status_code == 201
    task_id = created.json()['id']
    assert machine.post('/sensor/tasks/claim', headers=headers(context)).json()['task']['id'] == task_id
    assert machine.post(f'/sensor/tasks/{task_id}/start', headers=headers(context)).status_code == 200
    payload = {'task_type':'DISCOVER_NETWORK','observations':[{'ip_address':'192.168.1.55','hostname':'sensor-host'}]}
    result = machine.post(f'/sensor/tasks/{task_id}/result', headers=headers(context), json=payload)
    assert result.status_code == 200, result.text
    assert result.json() == {'task_id':task_id,'status':'COMPLETED','device_count':1}
    with get_connection(context['path']) as c:
        evidence = c.execute("SELECT source FROM device_observations WHERE ip_address='192.168.1.55'").fetchone()[0]
        assert evidence == f"remote-sensor:{sensor.record['sensor_uuid']}:task:{task_id}"
        assert c.execute('SELECT status FROM remote_sensor_tasks WHERE id=?',(task_id,)).fetchone()[0]=='COMPLETED'
    assert machine.post(f'/sensor/tasks/{task_id}/result', headers=headers(context), json=payload).status_code == 409
    assert machine.post(f'/sensor/tasks/{task_id}/result', headers=headers(context), json={**payload,'target_ip':'8.8.8.8'}).status_code == 422
    with get_connection(context['path']) as c:
        assert c.execute("SELECT COUNT(*) FROM device_observations WHERE source=?",(evidence,)).fetchone()[0] == 1


def test_out_of_scope_result_rejected_and_task_failed(context):
    store, admin, machine, sensor, scope = context['store'], context['admin'], context['machine'], context['sensor'], context['scope']
    task=admin.post(f"/sensors/{sensor.record['id']}/tasks/discover-network",json={'scope_id':scope['id']}).json()
    machine.post('/sensor/tasks/claim',headers=headers(context))
    machine.post(f"/sensor/tasks/{task['id']}/start",headers=headers(context))
    result=machine.post(f"/sensor/tasks/{task['id']}/result",headers=headers(context),json={
        'task_type':'DISCOVER_NETWORK','observations':[{'ip_address':'8.8.8.8'}]})
    assert result.status_code == 400
    with get_connection(store.db_path) as c:
        assert c.execute('SELECT status,error_code FROM remote_sensor_tasks WHERE id=?',(task['id'],)).fetchone()==('FAILED','RESULT_OUTSIDE_SCOPE')
        assert c.execute('SELECT COUNT(*) FROM devices WHERE last_ip_address=?',('8.8.8.8',)).fetchone()[0]==0


def test_service_task_result_uses_derived_device_and_existing_inventory(context):
    machine, admin, sensor, scope, device = context['machine'],context['admin'],context['sensor'],context['scope'],context['device']
    task=admin.post(f"/sensors/{sensor.record['id']}/tasks/discover-services",
                    json={'scope_id':scope['id'],'device_id':device['id']})
    assert task.status_code == 201
    claimed=machine.post('/sensor/tasks/claim',headers=headers(context)).json()['task']
    assert claimed['target_ip']=='192.168.1.20'
    task_id=task.json()['id']
    machine.post(f"/sensor/tasks/{task_id}/start",headers=headers(context))
    payload={'task_type':'DISCOVER_SERVICES','ports':[{'port':22}],
             'services':[{'port':22,'service_name':'ssh','product':'OpenSSH','version':'9.8'}]}
    result=machine.post(f"/sensor/tasks/{task_id}/result",headers=headers(context),json=payload)
    assert result.status_code == 200, result.text
    with get_connection(context['path']) as c:
        source=f"remote-sensor:{sensor.record['sensor_uuid']}:task:{task_id}"
        assert c.execute('SELECT ip_address,source FROM port_observations').fetchone()==('192.168.1.20',source)
        assert c.execute('SELECT source FROM service_observations').fetchone()[0]==source


def test_result_rejects_wrong_type_device_mutation_and_transport_replay(context):
    store, admin, machine, sensor, scope = context['store'],context['admin'],context['machine'],context['sensor'],context['scope']
    task=admin.post(f"/sensors/{sensor.record['id']}/tasks/discover-services",json={
        'scope_id':scope['id'],'device_id':context['device']['id']}).json()
    machine.post('/sensor/tasks/claim',headers=headers(context))
    machine.post(f"/sensor/tasks/{task['id']}/start",headers=headers(context))
    wrong=machine.post(f"/sensor/tasks/{task['id']}/result",headers=headers(context),json={
        'task_type':'DISCOVER_NETWORK','observations':[]})
    assert wrong.status_code == 400
    with get_connection(store.db_path) as c:
        c.execute('UPDATE devices SET last_ip_address=? WHERE id=?',('192.168.2.20',context['device']['id']))
    result=machine.post(f"/sensor/tasks/{task['id']}/result",headers=headers(context),json={
        'task_type':'DISCOVER_SERVICES','ports':[],'services':[]})
    assert result.status_code == 403


def test_no_execution_escape_routes_and_scope_assignment_is_management_only(context):
    machine, admin, sensor, scope = context['machine'],context['admin'],context['sensor'].record,context['scope']
    paths=machine.get('/openapi.json').json()['paths']
    assert '/sensor/tasks/claim' in paths
    assert '/sensor/tasks/{task_id}/result' in paths
    assert not any(term in p for p in paths for term in ('/shell','/execute','/scan','/jobs','/results'))
    for path in ('/sensor/tasks/1/execute','/sensor/tasks/1/scan','/sensor/tasks/1/shell'):
        assert machine.post(path,headers=headers(context),json={}).status_code in (404,405)
    assert machine.post(f"/sensors/{sensor['id']}/tasks/discover-network",headers=headers(context),
                        json={'scope_id':scope['id']}).status_code == 403
    assert machine.post(f"/sensors/{sensor['id']}/scope-assignments",headers=headers(context),
                        json={'scope_id':scope['id']}).status_code == 403


def test_operator_task_history_is_bounded_safe_and_read_only(context):
    store, sensor, scope, device = context['store'], context['sensor'].record, context['scope'], context['device']
    history = RemoteTaskStore(store)
    network_task = history.create_task(sensor['id'], scope['id'], 'DISCOVER_NETWORK')
    service_task = history.create_task(sensor['id'], scope['id'], 'DISCOVER_SERVICES', device_id=device['id'])
    with get_connection(store.db_path) as connection:
        connection.execute("""UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code=?,
            error_message=?,result_digest=?,created_by_source=? WHERE id=?""",
            ((NOW + timedelta(seconds=1)).isoformat(), 'SCANNER_TIMEOUT', 'raw exception / secret output',
             'private-digest', 'internal-source', network_task['id']))
        connection.execute('UPDATE remote_sensor_tasks SET created_at=? WHERE id=?',
                           ((NOW + timedelta(seconds=2)).isoformat(), network_task['id']))
        connection.execute("UPDATE remote_sensor_tasks SET expires_at=? WHERE id=?",
                           ((NOW - timedelta(seconds=1)).isoformat(), service_task['id']))
        before = connection.execute('SELECT * FROM remote_sensor_tasks ORDER BY id').fetchall()

    response = context['admin'].get('/sensor-tasks?limit=1')
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    body = response.json()
    assert body['limit'] == 1 and body['offset'] == 0 and body['has_more'] is True
    row = body['items'][0]
    assert row['id'] == network_task['id']
    assert row['status'] == 'FAILED' and row['expired'] is False
    assert row['failure_code'] == 'SCANNER_TIMEOUT'
    assert row['failure_message_safe'] == 'Sensor scanner timed out.'
    assert row['sensor_name'] == 'Sensor A' and row['site_name'] == 'Home'
    assert row['scope_name'] is not None and row['canonical_target'] == '192.168.1.0/24'
    assert set(row) == {
        'id', 'sensor_id', 'sensor_name', 'site_id', 'site_name', 'scope_id', 'scope_name',
        'canonical_target', 'target_device_id', 'target_ip', 'task_type', 'status', 'created_at',
        'expires_at', 'claimed_at', 'started_at', 'completed_at', 'failed_at', 'attempt_count',
        'failure_code', 'failure_message_safe', 'expired',
    }
    assert not any(key in row for key in ('error_message', 'result_digest', 'created_by_source', 'payload', 'result'))
    assert 'raw exception' not in response.text and 'private-digest' not in response.text
    with get_connection(store.db_path) as connection:
        after = connection.execute('SELECT * FROM remote_sensor_tasks ORDER BY id').fetchall()
    assert before == after


def test_operator_task_history_filters_expiry_and_safe_unknown_failure(context):
    store, sensor, scope, device = context['store'], context['sensor'].record, context['scope'], context['device']
    history = RemoteTaskStore(store)
    pending = history.create_task(sensor['id'], scope['id'], 'DISCOVER_NETWORK')
    service = history.create_task(sensor['id'], scope['id'], 'DISCOVER_SERVICES', device_id=device['id'])
    failed = history.create_task(sensor['id'], scope['id'], 'DISCOVER_NETWORK')
    with get_connection(store.db_path) as connection:
        connection.execute("UPDATE remote_sensor_tasks SET expires_at=? WHERE id=?",
                           ((NOW - timedelta(seconds=1)).isoformat(), pending['id']))
        connection.execute("UPDATE remote_sensor_tasks SET status='COMPLETED',error_code=?,completed_at=? WHERE id=?",
                           ('CANCELLED', NOW.isoformat(), service['id']))
        connection.execute("UPDATE remote_sensor_tasks SET status='FAILED',error_code=?,error_message=?,failed_at=? WHERE id=?",
                           ('SECRET_TRACE_VALUE', 'private traceback', NOW.isoformat(), failed['id']))
    response = context['admin'].get('/sensor-tasks', params={
        'sensor_id': sensor['id'], 'site_id': context['site']['id'], 'scope_id': scope['id'],
        'device_id': device['id'], 'task_type': 'DISCOVER_SERVICES', 'status': 'COMPLETED',
        'created_after': (NOW - timedelta(days=1)).isoformat(),
        'created_before': (NOW + timedelta(days=1)).isoformat(),
    })
    assert response.status_code == 200
    assert [row['id'] for row in response.json()['items']] == [service['id']]
    assert response.json()['items'][0]['expired'] is False
    overdue = context['admin'].get('/sensor-tasks', params={'sensor_id': sensor['id'], 'status': 'PENDING'}).json()
    assert overdue['items'][0]['expired'] is True
    unknown = context['admin'].get('/sensor-tasks', params={'sensor_id': sensor['id'], 'status': 'FAILED'}).json()
    assert unknown['items'][0]['failure_code'] == 'UNKNOWN_FAILURE'
    assert unknown['items'][0]['failure_message_safe'] == 'Unknown task failure.'
    assert 'SECRET_TRACE_VALUE' not in str(unknown) and 'private traceback' not in str(unknown)
    for params in (
        {'created_after': NOW.isoformat()},
        {'created_after': '2026-10-13T00:00:00', 'created_before': (NOW + timedelta(days=1)).isoformat()},
        {'created_after': NOW.isoformat(), 'created_before': (NOW - timedelta(seconds=1)).isoformat()},
        {'created_after': NOW.isoformat(), 'created_before': (NOW + timedelta(days=91)).isoformat()},
        {'device_id': 0},
    ):
        assert context['admin'].get('/sensor-tasks', params=params).status_code == 422


def test_operator_task_history_reuses_direct_local_boundary(context):
    assert context['machine'].get('/sensor-tasks').status_code == 403
    for headers_to_reject in (
        {'X-Forwarded-For': '127.0.0.1'},
        {'Forwarded': 'for=127.0.0.1'},
        {'Authorization': 'Bearer arbitrary'},
        {'X-SentinelIP-Sensor-ID': '1'},
        {'X-SentinelIP-Sensor-Token': 'secret'},
    ):
        response = context['admin'].get('/sensor-tasks', headers=headers_to_reject)
        assert response.status_code == 403


def test_task_history_evaluates_expiry_with_one_request_clock(context):
    task = create_network_task(context)
    calls = []
    fixed = context['clock'][0]
    context['store'].clock = lambda: calls.append(fixed) or fixed
    response = context['admin'].get('/sensor-tasks')
    assert response.status_code == 200
    assert response.json()['evaluated_at'] == fixed.isoformat()
    assert calls == [fixed]
    assert response.json()['items'][0]['id'] == task['id']


def test_operator_task_history_projects_every_persisted_state_without_marking_terminal_expired(context):
    store, sensor, scope = context['store'], context['sensor'].record, context['scope']
    history = RemoteTaskStore(store)
    statuses = ('PENDING', 'CLAIMED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')
    tasks = [history.create_task(sensor['id'], scope['id'], 'DISCOVER_NETWORK') for _ in statuses]
    with get_connection(store.db_path) as connection:
        for task, status in zip(tasks, statuses, strict=True):
            connection.execute('''UPDATE remote_sensor_tasks SET status=?,expires_at=?,attempt_count=2,
                failed_at=CASE WHEN ? IN ('FAILED','CANCELLED') THEN ? ELSE NULL END,
                completed_at=CASE WHEN ?='COMPLETED' THEN ? ELSE NULL END WHERE id=?''',
                (status, (NOW - timedelta(seconds=1)).isoformat(), status, NOW.isoformat(),
                 status, NOW.isoformat(), task['id']))
    response = context['admin'].get('/sensor-tasks?limit=100')
    assert response.status_code == 200
    rows = {row['id']: row for row in response.json()['items']}
    for task, status in zip(tasks, statuses, strict=True):
        row = rows[task['id']]
        assert row['status'] == status
        assert row['attempt_count'] == 2
        assert row['expired'] is (status not in {'COMPLETED', 'FAILED', 'CANCELLED'})
