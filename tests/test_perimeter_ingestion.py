import sqlite3
from datetime import datetime, timezone
from types import MethodType

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.perimeter_ingestion import register_perimeter_ingestion_routes
from api.sensor_enrollment import SensorBodyLimitMiddleware
from database.db import get_connection
from database.perimeter import persist_perimeter_events, query_perimeter_events
from database.remote_sensors import RemoteSensorStore
from sensor.client import CoreClient
from sensor.config import SensorConfig
from services.perimeter_ingestion import NetfilterKeyValueAdapter, PerimeterAdapterError
from services.perimeter_models import PerimeterEvent
from services.sensor_transport import authenticated_sensor_headers


NOW = datetime.now(timezone.utc).replace(microsecond=0)


def make_sensor(store, *, capabilities=('LOG_COLLECTION',)):
    site = store.create_site('Perimeter Site')
    invitation = store.create_enrollment(site['id'])
    issued = store.consume_enrollment(
        invitation.secret,
        sensor_uuid='11111111-1111-4111-8111-111111111111',
        name='Perimeter Sensor', platform='linux', version='1',
        reported_capabilities=list(capabilities),
    )
    return site, issued


def auth(issued):
    return authenticated_sensor_headers(
        issued.record['sensor_uuid'], issued.secret, now=NOW,
        nonce='A' * 43,
    )


def event_payload(**changes):
    value = {
        'external_event_id': 'router-0001',
        'source_type': 'FIREWALL',
        'source_key': 'wan-firewall',
        'observed_at': NOW.isoformat(),
        'event_type': 'POLICY_DECISION',
        'direction': 'INBOUND',
        'action': 'BLOCK',
        'protocol': 'TCP',
        'source_ip': '203.0.113.20',
        'destination_ip': '192.168.1.10',
        'source_port': 54000,
        'destination_port': 22,
        'interface': 'wan0',
        'source_reference': 'rule:wan-deny',
        'raw_event_hash': 'a' * 64,
        'metadata': {'rule': 'wan-deny'},
    }
    value.update(changes)
    return value


@pytest.fixture
def ingestion(tmp_path):
    store = RemoteSensorStore(tmp_path / 'perimeter-ingest.db', clock=lambda: NOW)
    app = FastAPI()
    register_perimeter_ingestion_routes(app, lambda: store, lambda: store.db_path)
    app.add_middleware(SensorBodyLimitMiddleware)
    with TestClient(app, base_url='https://core.test', client=('192.168.1.8', 5000)) as client:
        yield store, client


def test_machine_ingestion_derives_site_and_sensor_and_is_idempotent(ingestion):
    store, client = ingestion
    site, issued = make_sensor(store)
    response = client.post('/sensor/perimeter-events', headers=auth(issued), json={'events': [event_payload()]})
    assert response.status_code == 202
    assert response.json()['inserted'] == 1
    assert response.json()['idempotent'] == 0
    assert len(response.json()['detection_ids']) == 1

    replay_headers = authenticated_sensor_headers(
        issued.record['sensor_uuid'], issued.secret, now=NOW, nonce='B' * 43)
    replay = client.post('/sensor/perimeter-events', headers=replay_headers, json={'events': [event_payload()]})
    assert replay.status_code == 202
    assert replay.json()['inserted'] == 0 and replay.json()['idempotent'] == 1

    rows = query_perimeter_events(site_id=site['id'], db_path=store.db_path)
    assert rows['total'] == 1
    stored = rows['items'][0]
    assert stored['site_id'] == site['id']
    assert stored['sensor_id'] == issued.record['id']
    assert stored['source_ip'] == '203.0.113.20'


def test_sensor_requires_log_collection_capability(ingestion):
    store, client = ingestion
    _, issued = make_sensor(store, capabilities=('HOST_DISCOVERY',))
    response = client.post('/sensor/perimeter-events', headers=auth(issued), json={'events': [event_payload()]})
    assert response.status_code == 403
    assert query_perimeter_events(db_path=store.db_path)['total'] == 0


@pytest.mark.parametrize('extra', ['site_id', 'sensor_id', 'command', 'target', 'raw_log'])
def test_machine_payload_cannot_expand_authority_or_upload_raw_logs(ingestion, extra):
    store, client = ingestion
    _, issued = make_sensor(store)
    payload = event_payload(**{extra: 'untrusted'})
    response = client.post('/sensor/perimeter-events', headers=auth(issued), json={'events': [payload]})
    assert response.status_code == 422
    assert query_perimeter_events(db_path=store.db_path)['total'] == 0


def test_source_type_is_limited_to_perimeter_devices(ingestion):
    store, client = ingestion
    _, issued = make_sensor(store)
    response = client.post('/sensor/perimeter-events', headers=auth(issued), json={'events': [event_payload(source_type='SENSOR')]})
    assert response.status_code == 422


def test_invalid_model_and_sensitive_metadata_fail_closed(ingestion):
    store, client = ingestion
    _, issued = make_sensor(store)
    response = client.post('/sensor/perimeter-events', headers=auth(issued), json={
        'events': [event_payload(metadata={'token': 'secret'})]
    })
    assert response.status_code == 400
    assert response.json() == {'detail': 'Perimeter evidence is invalid.'}
    assert query_perimeter_events(db_path=store.db_path)['total'] == 0


def test_conflicting_identity_rolls_back_entire_batch(ingestion):
    store, client = ingestion
    _, issued = make_sensor(store)
    first = event_payload()
    created = client.post('/sensor/perimeter-events', headers=auth(issued), json={'events': [first]})
    assert created.status_code == 202

    conflict_headers = authenticated_sensor_headers(
        issued.record['sensor_uuid'], issued.secret, now=NOW, nonce='C' * 43)
    second = event_payload(external_event_id='router-0002', destination_port=443)
    conflict = event_payload(action='ALLOW')
    response = client.post('/sensor/perimeter-events', headers=conflict_headers, json={'events': [second, conflict]})
    assert response.status_code == 409
    assert query_perimeter_events(db_path=store.db_path)['total'] == 1


def test_database_batch_is_atomic_on_fk_failure(tmp_path):
    path = tmp_path / 'atomic.db'
    store = RemoteSensorStore(path)
    site = store.create_site('A')
    def direct_event(site_id, external_event_id):
        payload = event_payload(external_event_id=external_event_id)
        payload['observed_at'] = NOW
        return PerimeterEvent(site_id=site_id, sensor_id=None, **payload)

    valid = direct_event(site['id'], 'router-0001')
    invalid = direct_event(999999, 'other')
    with pytest.raises(sqlite3.IntegrityError):
        persist_perimeter_events([valid, invalid], path)
    assert query_perimeter_events(db_path=path)['total'] == 0


def test_netfilter_adapter_maps_only_network_facts_and_hashes_raw_line():
    adapter = NetfilterKeyValueAdapter(
        source_key='edge-fw', source_type='FIREWALL', direction='INBOUND', action='BLOCK',
        source_reference='rule:drop-wan',
    )
    raw = 'IN=wan0 OUT= SRC=203.0.113.9 DST=192.168.1.10 PROTO=TCP SPT=51000 DPT=22 SYN'
    observation = adapter.parse(raw, observed_at=NOW)
    wire = observation.to_wire()
    assert wire['source_ip'] == '203.0.113.9'
    assert wire['destination_ip'] == '192.168.1.10'
    assert wire['destination_port'] == 22
    assert wire['interface'] == 'wan0'
    assert wire['direction'] == 'INBOUND' and wire['action'] == 'BLOCK'
    assert len(wire['raw_event_hash']) == 64
    assert raw not in str(wire)


@pytest.mark.parametrize('raw', [
    'SRC=203.0.113.9 DST=192.168.1.10 PROTO=TCP',
    'SRC=not-an-ip DST=192.168.1.10 PROTO=TCP DPT=22',
    'SRC=203.0.113.9 DST=192.168.1.10 PROTO=TCP DPT=99999',
    'SRC=203.0.113.9 DST=192.168.1.10 PROTO=TCP DPT=22\nSRC=1.1.1.1',
])
def test_netfilter_adapter_rejects_ambiguous_or_invalid_lines(raw):
    adapter = NetfilterKeyValueAdapter(source_key='edge-fw', direction='INBOUND', action='BLOCK')
    with pytest.raises(PerimeterAdapterError):
        adapter.parse(raw, observed_at=NOW)


def test_core_client_exposes_only_structured_batch_method(tmp_path):
    config = SensorConfig(
        core_url='https://core.test', sensor_uuid='11111111-1111-4111-8111-111111111111',
        sensor_credential='x' * 43, grant_file=tmp_path / 'grants.json', capabilities=('LOG_COLLECTION',)
    )
    client = CoreClient(config)
    captured = {}

    def fake_call(self, method, path, body=None):
        captured.update(method=method, path=path, body=body)
        return {'accepted': 1}

    client._call = MethodType(fake_call, client)
    payload = event_payload()
    result = client.submit_perimeter_events([payload])
    assert result == {'accepted': 1}
    assert captured == {'method': 'POST', 'path': '/sensor/perimeter-events', 'body': {'events': [payload]}}
    with pytest.raises(ValueError):
        client.submit_perimeter_events([{**payload, 'raw_log': 'secret'}])


def test_log_collection_capability_is_opt_in_and_does_not_require_nmap(tmp_path, monkeypatch):
    import sensor.__main__ as sensor_main

    config = SensorConfig(
        core_url='https://core.test', sensor_uuid='11111111-1111-4111-8111-111111111111',
        sensor_credential='x' * 43, grant_file=tmp_path / 'grants.json',
        capabilities=('LOG_COLLECTION',),
    )
    monkeypatch.setattr(sensor_main, '_check_nmap', lambda: (_ for _ in ()).throw(AssertionError('nmap should not be required')))
    assert sensor_main._check_dependencies(config) is True
    args = sensor_main._parser().parse_args([
        'enroll', '--core-url', 'https://core.test', '--name', 'log-sensor',
        '--capability', 'LOG_COLLECTION',
    ])
    assert args.capability == ['LOG_COLLECTION']
