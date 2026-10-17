from datetime import datetime, timezone
import json
import uuid
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request

from api.investigation import register_investigation_routes
from api.remote_sensors import local_management
from database.db import get_connection, initialize_database, save_event
from database.incident_reviews import create_review
import database.investigation_lookup as lookup_module
from database.inventory import create_device
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.remote_tasks import RemoteTaskStore
from database.scopes import get_scope_for_network
from database.investigation_lookup import investigation_lookup

NOW = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
IP = '10.2.3.24'


@pytest.fixture
def lookup_context(tmp_path):
    path = tmp_path / 'investigation.db'
    store = RemoteSensorStore(path, clock=lambda: NOW)
    site = store.create_site('Research Site')
    enrollment = store.create_enrollment(site['id'])
    sensor = store.consume_enrollment(enrollment.secret, name='edge-01', platform='linux', version='1.0',
                                      reported_capabilities=['HOST_DISCOVERY', 'SERVICE_DISCOVERY'])
    network = create_network('10.2.3.0/24', 'Research LAN', '', True, True, path)
    scope = get_scope_for_network(network['id'], path)
    store.assign_scope(sensor.record['id'], scope['id'])
    device = create_device(stable_key='lookup-device-1', network_id=network['id'], mac_address=None,
        hostname='device-label', vendor='vendor-label', first_seen=NOW.isoformat(), last_seen=NOW.isoformat(),
        last_ip_address=IP, status='ONLINE', identity_confidence='HIGH', db_path=path)
    review = create_review(title='Review title', site_id=site['id'], scope_id=scope['id'],
        device_id=device['id'], analyst_note='PRIVATE NOTE', final_summary='PRIVATE SUMMARY', db_path=path)
    task = RemoteTaskStore(store).create_task(sensor.record['id'], scope['id'], 'DISCOVER_SERVICES',
                                               device_id=device['id'])
    app = FastAPI()
    register_investigation_routes(app, lambda: path)
    endpoint = next(route.endpoint for route in app.routes
                    if getattr(route, 'path', None) == '/investigation-lookup')
    yield {'path': path, 'store': store, 'site': site, 'sensor': sensor,
           'network': network, 'scope': scope, 'device': device,
           'review': review, 'task': task, 'app': app, 'endpoint': endpoint}


def _call(context, params, headers=None, *, client=('127.0.0.1', 5050), host='127.0.0.1'):
    query_string = urlencode(list(params.items()), doseq=True).encode()
    raw_headers = [(b'host', host.encode())]
    raw_headers.extend((key.lower().encode(), value.encode()) for key, value in (headers or {}).items())
    request = Request({'type':'http','asgi':{'version':'3.0','spec_version':'2.3'},'http_version':'1.1',
        'method':'GET','scheme':'http','path':'/investigation-lookup','raw_path':b'/investigation-lookup',
        'query_string':query_string,'root_path':'','headers':raw_headers,'client':client,
        'server':('127.0.0.1',8000)})
    response = Response()
    try:
        local_management(request, response)
        args = {key: request.query_params.get(key) for key in ('query_type','value','evidence_type','evidence_id')}
        result = context['endpoint'](request=request, response=response, **args)
        return SimpleNamespace(status_code=200, headers=response.headers, json=lambda: result)
    except HTTPException as exc:
        return SimpleNamespace(status_code=exc.status_code, headers=response.headers,
                               json=lambda: {'detail':exc.detail})


def _item(response):
    assert response.status_code == 200
    return response.json()['items'][0]


def test_primary_lookups_have_fixed_safe_envelope_and_direct_local_no_store(lookup_context):
    c = lookup_context
    cases = [
        ('DEVICE_ID', c['device']['id'], 'DEVICE'),
        ('SENSOR_ID', c['sensor'].record['id'], 'SENSOR'),
        ('SITE_ID', c['site']['id'], 'SITE'),
        ('SCOPE_ID', c['scope']['id'], 'SCOPE'),
        ('INCIDENT_REVIEW_ID', c['review']['id'], 'INCIDENT_REVIEW'),
        ('INCIDENT_REVIEW_KEY', c['review']['incident_key'], 'INCIDENT_REVIEW'),
        ('TASK_ID', c['task']['id'], 'SENSOR_TASK'),
    ]
    expected_keys = {'entity_type','entity_id','label','context_label','site_id','site_name',
        'scope_id','scope_name','device_id','sensor_id','occurred_at','destination_kind','destination_id'}
    for query_type, value, entity_type in cases:
        response = _call(c, {'query_type': query_type, 'value': value})
        item = _item(response)
        assert item['entity_type'] == entity_type
        assert set(item) == expected_keys
        assert isinstance(item['entity_id'], str) and isinstance(item['destination_id'], str)
        assert response.headers['cache-control'] == 'no-store'
        encoded = json.dumps(response.json()).lower()
        for forbidden in ('credential_hash','credential_salt','token_hash','result_digest',
                          'created_by_source','error_message','private note','private summary'):
            assert forbidden not in encoded
    sensor_item = _call(c, {'query_type':'SENSOR_ID','value':c['sensor'].record['id']}).json()['items'][0]
    assert sensor_item['context_label'].startswith('PENDING · linux · 1.0')
    assert sensor_item['site_name'] == 'Research Site'
    task_item = _call(c, {'query_type':'TASK_ID','value':c['task']['id']}).json()['items'][0]
    assert task_item['destination_id'] == c['task']['id']
    assert task_item['device_id'] == c['device']['id']


@pytest.mark.parametrize(('query_type','value'), [
    ('NOPE','1'), ('DEVICE_ID',''), ('DEVICE_ID','   '), ('DEVICE_ID','0'),
    ('DEVICE_ID','-1'), ('DEVICE_ID','1.2'), ('DEVICE_ID','+1'),
    ('INCIDENT_REVIEW_KEY','IR-ABCDEF'), ('INCIDENT_REVIEW_KEY','IR-'+'A'*32),
    ('TASK_ID','not-a-uuid'), ('TASK_ID',str(uuid.uuid4()).upper()),
    ('IP_ADDRESS','2001:db8::1'), ('IP_ADDRESS','10.2.3.0/24'),
    ('IP_ADDRESS','host.example'), ('IP_ADDRESS','192.0.*.24'), ('IP_ADDRESS','192.0.2'),
    ('IP_ADDRESS','192.000.2.24'), ('IP_ADDRESS',' 10.2.3.24'),
])
def test_invalid_lookup_values_are_422(lookup_context, query_type, value):
    response = _call(lookup_context, {'query_type':query_type, 'value':value})
    assert response.status_code == 422


def test_evidence_reference_uses_fixed_allowlist_and_missing_is_empty(lookup_context):
    c = lookup_context
    with get_connection(c['path']) as db:
        event_id = db.execute("""INSERT INTO perimeter_events(
            external_event_id,site_id,source_type,source_key,event_type,direction,action,protocol,
                source_ip,destination_ip,destination_port,observed_at,received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ('ev1',c['site']['id'],'FIREWALL','fw1','FLOW','INBOUND','BLOCK','TCP',IP,'198.51.100.2',443,NOW.isoformat(),NOW.isoformat())).lastrowid
        threat_id = db.execute("""INSERT INTO threat_detections(
            stable_key,threat_type,state,severity,confidence,device_id,source_ip,primary_evidence_type,
            primary_evidence_id,anchor_id,reason,recommendation,rule_id,rule_version,first_seen,last_seen,created_at,updated_at)
            VALUES ('th-1','SSH_BRUTE_FORCE_THREAT','SUSPECTED','HIGH','MEDIUM',?,?,'SSH_EVENT',1,1,'raw reason','raw recommendation','r1','1',?,?,?,?)""",
            (c['device']['id'],IP,NOW.isoformat(),NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        perimeter_detection = db.execute("""INSERT INTO perimeter_detections(
            stable_key,detection_type,state,confidence,site_id,primary_event_id,event_ids_json,source_ip,
            destination_ip,destination_port,protocol,action,event_count,unique_source_count,first_seen,last_seen,rule_id,rule_version,reason,created_at)
            VALUES ('pd-1','INBOUND_ATTEMPT','REVIEW','HIGH',?,?, '[1]', ?, '198.51.100.2',443,'TCP','BLOCK',1,1,?,?, 'r1','1','raw reason',?)""",
            (c['site']['id'],event_id,IP,NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        policy_id = db.execute("""INSERT INTO perimeter_policy_correlations(
            stable_key,correlation_type,state,confidence,site_id,primary_event_id,event_ids_json,allowed_event_ids_json,
            blocked_event_ids_json,source_type,source_key,source_ip,destination_ip,destination_port,protocol,primary_action,event_count,
            allow_count,blocked_count,first_seen,last_seen,rule_id,rule_version,reason,created_at)
            VALUES ('pc-1','BLOCK_THEN_ALLOW','REVIEW','HIGH',?,?, '[1,2]','[1]','[2]','FIREWALL','fw1',?,'198.51.100.2',443,'TCP','BLOCK',2,1,1,?,?, 'r1','1','raw reason',?)""",
            (c['site']['id'],event_id,IP,NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        host_id = db.execute("""INSERT INTO perimeter_host_correlations(
            stable_key,correlation_type,state,confidence,site_id,event_id,scope_id,network_id,device_id,destination_ip,
            destination_port,protocol,action,observed_at,device_last_seen,device_status,identity_confidence,rule_id,rule_version,reason,created_at)
            VALUES ('ph-1','DESTINATION_DEVICE_MATCH','REVIEW','HIGH',?,?,?,?,?,?,443,'TCP','ALLOW',?,?, 'ONLINE','HIGH','r1','1','raw reason',?)""",
            (c['site']['id'],event_id,c['scope']['id'],c['network']['id'],c['device']['id'],IP,NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        # Exposure table uses an explicit scope and device relation; raw change values remain excluded.
        exposure_id = db.execute("""INSERT INTO external_exposures(
            stable_key,scope_id,scope_type,canonical_target,device_id,target_ip,port_number,transport,
            first_seen,last_seen,last_observation_source,last_scanner,created_at,updated_at)
            VALUES ('ex-1',?,'PUBLIC_IPV4','198.51.100.7',?,'198.51.100.7',443,'tcp',?,?, 'source','scanner',?,?)""",
            (c['scope']['id'],c['device']['id'],NOW.isoformat(),NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        change_id = db.execute("""INSERT INTO external_exposure_changes(
            event_key,exposure_id,scope_id,change_type,previous_value,current_value,reason,observed_at,source,scanner,created_at)
            VALUES ('change-1',?,?,'NEW_EXPOSURE','raw previous','raw current','raw reason',?,'source','scanner',?)""",
            (exposure_id,c['scope']['id'],NOW.isoformat(),NOW.isoformat())).lastrowid
        correlation_id = db.execute("""INSERT INTO correlations(
            stable_key,correlation_type,state,severity,confidence,device_id,source_ip,primary_entity_type,
            primary_entity_id,reason,rule_id,rule_version,first_seen,last_seen,created_at,updated_at)
            VALUES ('co-1','SSH_AUTH_ACTIVITY_PATTERN','PATTERN','MEDIUM','MEDIUM',?,?,'THREAT',?,'raw reason','r1','1',?,?,?,?)""",
            (c['device']['id'],IP,threat_id,NOW.isoformat(),NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid

    ids = {
        'THREAT_DETECTION':threat_id,
        'THREAT_CORRELATION':correlation_id,
        'PERIMETER_DETECTION':perimeter_detection,
        'PERIMETER_POLICY_CORRELATION':policy_id,
        'PERIMETER_HOST_CORRELATION':host_id,
        'EXTERNAL_EXPOSURE_CHANGE':change_id,
    }
    for evidence_type, evidence_id in ids.items():
        result = _call(c, {'query_type':'EVIDENCE_REFERENCE','evidence_type':evidence_type,'evidence_id':evidence_id})
        assert result.status_code == 200
        assert len(result.json()['items']) == 1
        assert result.json()['items'][0]['entity_type'] == evidence_type
        assert set(result.json()['items'][0]) == set(_call(c,{'query_type':'DEVICE_ID','value':c['device']['id']}).json()['items'][0])
    ip_results = investigation_lookup('IP_ADDRESS',value=IP,db_path=c['path'])['items']
    ip_types = {item['entity_type'] for item in ip_results}
    assert {'DEVICE','PERIMETER_EVENT','THREAT_DETECTION','THREAT_CORRELATION',
            'PERIMETER_DETECTION','PERIMETER_POLICY_CORRELATION',
            'PERIMETER_HOST_CORRELATION'} <= ip_types
    assert next(item for item in ip_results if item['entity_type']=='PERIMETER_EVENT')['site_name'] == 'Research Site'
    assert _call(c, {'query_type':'EVIDENCE_REFERENCE','evidence_type':'WEB_DETECTION','evidence_id':1}).status_code == 422
    assert _call(c, {'query_type':'EVIDENCE_REFERENCE','evidence_type':'THREAT_DETECTION','evidence_id':0}).status_code == 422
    assert _call(c, {'query_type':'EVIDENCE_REFERENCE','evidence_type':'THREAT_DETECTION','value':'1','evidence_id':1}).status_code == 422
    assert _call(c, {'query_type':'EVIDENCE_REFERENCE','evidence_type':'THREAT_DETECTION','evidence_id':999}).json()['items'] == []


def test_ip_lookup_sources_context_dedup_order_and_caps(lookup_context):
    c = lookup_context
    # Private IP device identity is explicit; do not infer a site from range membership.
    save_event(NOW.isoformat(), IP, None, 'LOGIN', 'WARNING', 'Do not expose arbitrary message', 1, c['path'])
    with get_connection(c['path']) as db:
        # Legacy events demonstrate per-type truncation and raw message exclusion.
        for index in range(12):
            db.execute("INSERT INTO events(timestamp,source_ip,username,event_type,severity,message,event_count) VALUES (?,?,?,?,?,?,?)",
                (NOW.isoformat(), IP, None, 'LOGIN', 'ALERT', f'private-message-{index}', 1))
    result = investigation_lookup('IP_ADDRESS', value=IP, db_path=c['path'])
    assert result['truncated'] is True
    assert len([i for i in result['items'] if i['entity_type'] == 'LEGACY_EVENT']) == 5
    assert len({(i['entity_type'],i['entity_id']) for i in result['items']}) == len(result['items'])
    event_ids = [int(i['entity_id']) for i in result['items'] if i['entity_type'] == 'LEGACY_EVENT']
    assert event_ids == sorted(event_ids, reverse=True)
    assert not any('private-message' in json.dumps(i) or 'message' in i for i in result['items'])
    assert result['items'][0]['occurred_at'] is not None
    assert all(set(i) == set(result['items'][0]) for i in result['items'])


def test_ip_lookup_enforces_global_cap_after_per_type_caps(lookup_context, monkeypatch):
    c = lookup_context
    for index in range(4):
        create_device(stable_key=f'global-cap-{index}', network_id=c['network']['id'], mac_address=None,
            hostname=None, vendor=None, first_seen=NOW.isoformat(), last_seen=NOW.isoformat(),
            last_ip_address=IP, status='ONLINE', identity_confidence='HIGH', db_path=c['path'])
    with get_connection(c['path']) as db:
        for index in range(8):
            db.execute("INSERT INTO events(timestamp,source_ip,username,event_type,severity,message,event_count) VALUES (?,?,?,?,?,?,?)",
                (NOW.isoformat(), IP, None, 'LOGIN', 'INFO', f'private-{index}', 1))
    monkeypatch.setattr(lookup_module, 'IP_GLOBAL_LIMIT', 3)
    result = investigation_lookup('IP_ADDRESS', value=IP, db_path=c['path'])
    assert len(result['items']) == 3
    assert result['truncated'] is True


def test_ip_lookup_includes_public_ipv4_scope_only_for_exact_host(lookup_context):
    c = lookup_context
    with get_connection(c['path']) as db:
        db.execute("""INSERT INTO authorized_scopes(scope_type,canonical_target,name,description,authorized,enabled,
            authorization_confirmed_at,authorization_confirmation_version,authorization_source,created_at,updated_at)
            VALUES ('PUBLIC_IPV4','198.51.100.7','Public host','',1,1,?,'v1','operator',?,?)""",
            (NOW.isoformat(),NOW.isoformat(),NOW.isoformat()))
    exact = investigation_lookup('IP_ADDRESS',value='198.51.100.7',db_path=c['path'])
    assert any(item['entity_type']=='SCOPE' for item in exact['items'])
    inside_unmatched_range = investigation_lookup('IP_ADDRESS',value='10.2.3.25',db_path=c['path'])
    assert not any(item['entity_type']=='SCOPE' for item in inside_unmatched_range['items'])


def test_ip_lookup_includes_exposure_and_changes_through_explicit_exposure_target(lookup_context):
    c = lookup_context
    target = '198.51.100.7'
    with get_connection(c['path']) as db:
        scope_id = db.execute("""INSERT INTO authorized_scopes(scope_type,canonical_target,name,description,authorized,enabled,
            authorization_confirmed_at,authorization_confirmation_version,authorization_source,created_at,updated_at)
            VALUES ('PUBLIC_IPV4',?,'External scope','',1,1,?,'v1','operator',?,?)""",
            (target,NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        exposure_id = db.execute("""INSERT INTO external_exposures(
            stable_key,scope_id,scope_type,canonical_target,device_id,target_ip,port_number,transport,
            first_seen,last_seen,last_observation_source,last_scanner,created_at,updated_at)
            VALUES ('exp-public',?,'PUBLIC_IPV4',?,?,?,443,'tcp',?,?, 'source','scanner',?,?)""",
            (scope_id,target,c['device']['id'],target,NOW.isoformat(),NOW.isoformat(),NOW.isoformat(),NOW.isoformat())).lastrowid
        db.execute("""INSERT INTO external_exposure_changes(
            event_key,exposure_id,scope_id,change_type,previous_value,current_value,reason,observed_at,source,scanner,created_at)
            VALUES ('change-public',?,?,'NEW_EXPOSURE','raw old','raw new','raw reason',?,'source','scanner',?)""",
            (exposure_id,scope_id,NOW.isoformat(),NOW.isoformat()))
    result = investigation_lookup('IP_ADDRESS',value=target,db_path=c['path'])
    assert {'SCOPE','EXTERNAL_EXPOSURE','EXTERNAL_EXPOSURE_CHANGE'} <= {item['entity_type'] for item in result['items']}


def test_unknown_ids_empty_and_lookup_read_only(lookup_context):
    c = lookup_context
    with get_connection(c['path']) as db:
        before = {table: db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                  for table in ('devices','remote_sensors','sites','authorized_scopes','incident_reviews','remote_sensor_tasks')}
    for query_type, value in [('DEVICE_ID','999999'),('SENSOR_ID','999999'),('SITE_ID','999999'),
                              ('SCOPE_ID','999999'),('INCIDENT_REVIEW_ID','999999'),
                              ('TASK_ID',str(uuid.uuid4()))]:
        assert investigation_lookup(query_type,value=value,db_path=c['path'])['items'] == []
    with get_connection(c['path']) as db:
        after = {table: db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                 for table in before}
    assert before == after


def test_endpoint_rejects_extra_params_and_reuses_local_management_boundary(lookup_context):
    c = lookup_context
    good = _call(c, {'query_type':'SITE_ID','value':c['site']['id']})
    assert good.status_code == 200 and good.headers['cache-control'] == 'no-store'
    assert _call(c, {'query_type':'SITE_ID','value':1,'extra':'x'}).status_code == 422
    assert _call(c, {'query_type':['SITE_ID','SITE_ID'],'value':1}).status_code == 422
    assert _call(c, {'query_type':'SITE_ID','value':1},headers={'x-forwarded-for':'127.0.0.1'}).status_code == 403
    assert _call(c, {'query_type':'SITE_ID','value':1},headers={'authorization':'Bearer x'}).status_code == 403
    assert _call(c, {'query_type':'SITE_ID','value':1},headers={'x-sentinelip-sensor-id':'1'}).status_code == 403
    assert _call(c, {'query_type':'SITE_ID','value':1},client=('192.0.2.1',5050)).status_code == 403
    route = next(route for route in c['app'].routes if getattr(route,'path',None)=='/investigation-lookup')
    assert any(dependency.dependency is local_management for dependency in route.dependencies)


def test_ip_query_plans_use_expected_indexes(lookup_context):
    c = lookup_context
    checks = [
        ('EXPLAIN QUERY PLAN SELECT id FROM devices WHERE last_ip_address=?',(IP,), 'idx_devices_last_ip_address'),
        ('EXPLAIN QUERY PLAN SELECT id FROM events WHERE source_ip=?',(IP,), 'idx_events_threat_window'),
        ('EXPLAIN QUERY PLAN SELECT id FROM threat_detections WHERE source_ip=?',(IP,), 'idx_threat_detections_source_time'),
        ('EXPLAIN QUERY PLAN SELECT id FROM correlations WHERE source_ip=?',(IP,), 'idx_correlations_source'),
        ('EXPLAIN QUERY PLAN SELECT id FROM perimeter_events WHERE source_ip=? OR destination_ip=?',(IP,IP), 'idx_perimeter_'),
        ('EXPLAIN QUERY PLAN SELECT id FROM perimeter_detections WHERE source_ip=? OR destination_ip=?',(IP,IP), 'idx_perimeter_detections_'),
        ('EXPLAIN QUERY PLAN SELECT id FROM perimeter_policy_correlations WHERE source_ip=? OR destination_ip=?',(IP,IP), 'idx_perimeter_policy_'),
        ('EXPLAIN QUERY PLAN SELECT id FROM perimeter_host_correlations WHERE destination_ip=?',(IP,), 'idx_perimeter_host_destination'),
        ('EXPLAIN QUERY PLAN SELECT id FROM external_exposures WHERE target_ip=?',(IP,), 'idx_external_exposures_target_port'),
        ('EXPLAIN QUERY PLAN SELECT c.id FROM external_exposure_changes c JOIN external_exposures e ON e.id=c.exposure_id WHERE e.target_ip=? ORDER BY julianday(c.observed_at) DESC,c.id DESC LIMIT 6',(IP,), 'idx_external_exposures_target_port'),
        ("EXPLAIN QUERY PLAN SELECT id FROM authorized_scopes WHERE scope_type='PUBLIC_IPV4' AND canonical_target=? ORDER BY id LIMIT 1",(IP,), 'sqlite_autoindex_authorized_scopes_1'),
    ]
    for sql, params, expected in checks:
        with get_connection(c['path']) as db:
            plan = ' '.join(str(row[3]) for row in db.execute(sql,params))
        assert expected in plan, (sql,plan)


def test_schema_remains_43(lookup_context):
    with get_connection(lookup_context['path']) as db:
        assert db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 43
