from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import api.main as api
from database.db import get_connection, initialize_database
from database.incident_reviews import (
    IncidentReviewError, add_evidence, create_review, get_review, list_evidence,
    list_reviews, remove_evidence, update_review,
)
from database.inventory import create_device, create_scope_device
from database.migrations import MIGRATIONS
from database.networks import create_network
from database.perimeter import persist_perimeter_event
from database.perimeter_detections import get_perimeter_detection
from database.remote_sensors import RemoteSensorStore
from database.scopes import create_scope
from services.perimeter_detection_engine import PerimeterDetectionEngine
from services.perimeter_models import PerimeterEvent

AT = datetime(2026, 10, 13, 11, 0, tzinfo=timezone.utc)


def _detection(path, site_id, sequence):
    at = AT + timedelta(minutes=sequence)
    event = PerimeterEvent(
        external_event_id=f'review-fw-{sequence}', site_id=site_id, sensor_id=None,
        source_type='FIREWALL', source_key='review-test', observed_at=at,
        event_type='POLICY_DECISION', direction='INBOUND', action='BLOCK', protocol='TCP',
        source_ip='203.0.113.8', destination_ip='192.168.1.12', source_port=44000+sequence,
        destination_port=22, interface='wan0', source_reference='rule:test',
        raw_event_hash=f'{sequence:064x}', metadata=None,
    )
    event_row = persist_perimeter_event(event, path)
    return PerimeterDetectionEngine(path).evaluate_event(event_row['id'])


def _review_db(path):
    return create_review(title='Inbound activity review',site_id=None,db_path=path)


def _private_device(path, site_name, cidr):
    site = RemoteSensorStore(path).create_site(site_name)
    network = create_network(cidr,site_name,'review fixture',True,True,path)
    with get_connection(path) as connection:
        scope_id = connection.execute('SELECT scope_id FROM network_scope_links WHERE network_id=?',
                                      (network['id'],)).fetchone()[0]
        connection.execute('INSERT INTO remote_scope_sites(scope_id,site_id,created_at) VALUES (?,?,?)',
                           (scope_id,site['id'],AT.isoformat()))
    device = create_device(f'review:{cidr}',network['id'],None,None,None,AT.isoformat(),AT.isoformat(),
                           str(network['cidr'].split('/')[0]),'ONLINE','HIGH',path)
    return site,scope_id,device


def _device_threat(path,device_id,sequence=1):
    at = (AT + timedelta(minutes=sequence)).isoformat()
    with get_connection(path) as connection:
        cursor = connection.execute('''INSERT INTO threat_detections (
            stable_key,threat_type,state,severity,confidence,device_id,source_ip,sensor_id,hostname,
            primary_evidence_type,primary_evidence_id,anchor_id,reason,recommendation,rule_id,rule_version,
            first_seen,last_seen,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (f'review-threat-{sequence}','SUSPICIOUS_AUTH_ACTIVITY','ANOMALOUS','LOW','MEDIUM',device_id,
             '203.0.113.20',None,None,'SSH_EVENT',sequence,sequence,'review signal','review evidence',
             'review.test','1',at,at,at,at))
        return cursor.lastrowid


def test_migration_41_is_additive_idempotent_and_fk_clean(tmp_path,monkeypatch):
    path = tmp_path / 'review-migration.db'
    from database import migrations as migration_module
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS[:40])
    initialize_database(path)
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS)
    # Apply the full initialization twice, as production startup does.
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM schema_migrations WHERE version=41').fetchone()[0] == 1
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {'incident_reviews','incident_review_evidence','incidents','incident_correlations'} <= names
        assert max(version for version,_ in MIGRATIONS) == 41


def test_create_link_idempotency_time_recomputation_and_detach_preserves_source(tmp_path):
    path = tmp_path / 'review.db'
    site = RemoteSensorStore(path).create_site('Review site')
    first = _detection(path,site['id'],1)
    second = _detection(path,site['id'],2)
    review = create_review(title='Inbound attempts for analyst review',site_id=site['id'],
                           state='IN_REVIEW',priority='HIGH',confidence='MEDIUM',db_path=path)
    linked = add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=first['id'],db_path=path)
    assert linked['idempotent'] is False
    replay = add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=first['id'],db_path=path)
    assert replay['idempotent'] is True
    add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=second['id'],db_path=path)
    current = get_review(review['id'],path)
    assert current['first_evidence_at'] == first['first_seen']
    assert current['last_evidence_at'] == second['first_seen']
    assert list_evidence(review['id'],db_path=path)['total'] == 2
    remove_evidence(review['id'],'PERIMETER_DETECTION',first['id'],path)
    current = get_review(review['id'],path)
    assert current['first_evidence_at'] == second['first_seen'] == current['last_evidence_at']
    assert get_perimeter_detection(first['id'],path) is not None
    remove_evidence(review['id'],'PERIMETER_DETECTION',second['id'],path)
    assert get_review(review['id'],path)['first_evidence_at'] is None


def test_closed_update_and_strict_enum_and_evidence_validation(tmp_path):
    path = tmp_path / 'review-validation.db'
    review = _review_db(path)
    closed = update_review(review['id'],{'state':'CLOSED','disposition':'INCONCLUSIVE'},path)
    assert closed['closed_at'] and closed['state'] == 'CLOSED'
    reopened = update_review(review['id'],{'state':'OPEN'},path)
    assert reopened['closed_at'] is None
    with pytest.raises(IncidentReviewError):
        create_review(title='bad',priority='COMPROMISED',db_path=path)
    with pytest.raises(IncidentReviewError):
        update_review(review['id'],{'title':None},path)
    with pytest.raises(IncidentReviewError):
        add_evidence(review['id'],evidence_type='events',evidence_id=1,db_path=path)
    with pytest.raises(IncidentReviewError) as exc:
        add_evidence(review['id'],evidence_type='THREAT_DETECTION',evidence_id=999999,db_path=path)
    assert exc.value.status_code == 404


def test_attribution_consistency_rejects_cross_site_evidence(tmp_path):
    path = tmp_path / 'review-attribution.db'
    first_site = RemoteSensorStore(path).create_site('First')
    second_site = RemoteSensorStore(path).create_site('Second')
    evidence = _detection(path,second_site['id'],1)
    review = create_review(title='Scoped review',site_id=first_site['id'],db_path=path)
    with pytest.raises(IncidentReviewError,match='site_id'):
        add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=evidence['id'],db_path=path)


def test_incident_review_api_create_filter_attach_patch_and_source_immutability(tmp_path,monkeypatch):
    path = tmp_path / 'review-api.db'
    initialize_database(path)
    monkeypatch.setattr(api,'DB_PATH',path)
    site = RemoteSensorStore(path).create_site('API review site')
    source = _detection(path,site['id'],3)
    before = get_perimeter_detection(source['id'],path)
    with TestClient(api.app) as client:
        made = client.post('/incident-reviews',json={'title':'Analyst review','site_id':site['id'],
            'priority':'HIGH','confidence':'MEDIUM'})
        assert made.status_code == 201, made.text
        incident_id = made.json()['id']
        attached = client.post(f'/incident-reviews/{incident_id}/evidence',json={
            'evidence_type':'PERIMETER_DETECTION','evidence_id':source['id'],'reason':'Review queue'})
        assert attached.status_code == 201 and attached.json()['observed_at'] == before['first_seen']
        assert client.get('/incident-reviews?state=OPEN&priority=HIGH').json()['total'] == 1
        changed = client.patch(f'/incident-reviews/{incident_id}',json={
            'state':'CLOSED','disposition':'NEEDS_MONITORING','analyst_note':'Check next week'})
        assert changed.status_code == 200 and changed.json()['closed_at']
        assert client.get(f'/incident-reviews/{incident_id}/evidence').json()['total'] == 1
        assert client.delete(f'/incident-reviews/{incident_id}/evidence/FAKE/1').status_code == 422
        assert client.delete(f'/incident-reviews/{incident_id}/evidence/PERIMETER_DETECTION/{source["id"]}').status_code == 200
        assert get_perimeter_detection(source['id'],path) == before
        assert client.post(f'/incident-reviews/{incident_id}/evidence',json={
            'evidence_type':'PERIMETER_DETECTION','evidence_id':999999}).status_code == 404
        assert client.post('/incident-reviews',json={'title':'bad','table':'events'}).status_code == 422


def test_source_attribution_must_be_consistent_across_links(tmp_path):
    path = tmp_path / 'review-mixed.db'
    site_a = RemoteSensorStore(path).create_site('A')
    site_b = RemoteSensorStore(path).create_site('B')
    a = _detection(path,site_a['id'],4)
    b = _detection(path,site_b['id'],5)
    review = create_review(title='One site review',db_path=path)
    add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=a['id'],db_path=path)
    with pytest.raises(IncidentReviewError,match='conflicting site_id'):
        add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=b['id'],db_path=path)


def test_review_site_scope_device_relationships_fail_closed(tmp_path):
    path = tmp_path / 'review-device-attribution.db'
    site_a,scope_a,device_a = _private_device(path,'A','192.168.10.0/24')
    site_b,scope_b,device_b = _private_device(path,'B','192.168.20.0/24')
    compatible = create_review(title='Compatible',site_id=site_a['id'],scope_id=scope_a,
                               device_id=device_a['id'],db_path=path)
    assert compatible['device_id'] == device_a['id']
    for args in (
        {'site_id':site_a['id'],'device_id':device_b['id']},
        {'scope_id':scope_a,'device_id':device_b['id']},
        {'site_id':site_a['id'],'scope_id':scope_b},
    ):
        with pytest.raises(IncidentReviewError):
            create_review(title='Contradiction',db_path=path,**args)
    site_only = create_review(title='Site only',site_id=site_a['id'],db_path=path)
    with pytest.raises(IncidentReviewError,match='unambiguous'):
        update_review(site_only['id'],{'device_id':device_b['id']},path)
    # A device with no site/scope binding cannot be guessed into a site.
    network_c = create_network('192.168.30.0/24','Unbound','review fixture',True,True,path)
    unbound = create_device('review:unbound',network_c['id'],None,None,None,AT.isoformat(),AT.isoformat(),
                            '192.168.30.1','ONLINE','HIGH',path)
    with pytest.raises(IncidentReviewError,match='unambiguous'):
        create_review(title='Ambiguous relation',site_id=site_a['id'],device_id=unbound['id'],db_path=path)


def test_patch_revalidates_merged_attribution_and_evidence_resolves_device_site(tmp_path):
    path = tmp_path / 'review-merged-attribution.db'
    site_a,scope_a,device_a = _private_device(path,'A','192.168.40.0/24')
    site_b,scope_b,device_b = _private_device(path,'B','192.168.50.0/24')
    review = create_review(title='Merged patch',site_id=site_a['id'],scope_id=scope_a,db_path=path)
    with pytest.raises(IncidentReviewError):
        update_review(review['id'],{'device_id':device_b['id']},path)
    threat_id = _device_threat(path,device_a['id'])
    linked = create_review(title='Device evidence',site_id=site_a['id'],db_path=path)
    link = add_evidence(linked['id'],evidence_type='THREAT_DETECTION',evidence_id=threat_id,db_path=path)
    assert link['evidence_id'] == threat_id
    unrelated = create_review(title='Wrong site',site_id=site_b['id'],db_path=path)
    with pytest.raises(IncidentReviewError,match='site_id'):
        add_evidence(unrelated['id'],evidence_type='THREAT_DETECTION',evidence_id=threat_id,db_path=path)
    # The explicit scope path for public inventory devices is also checked.
    public_scope = create_scope(scope_type='PUBLIC_IPV4',canonical_target='8.8.8.8',name='A public',
        description='review fixture',authorized=True,enabled=True,authorization_confirmed_at=AT.isoformat(),
        authorization_confirmation_version='test',authorization_source='test',db_path=path)
    public_device = create_scope_device(public_scope['id'],first_seen=AT.isoformat(),last_seen=AT.isoformat(),
                                        status='ONLINE',db_path=path)
    with pytest.raises(IncidentReviewError):
        create_review(title='Wrong public device scope',scope_id=public_scope['id'],
                      device_id=device_a['id'],db_path=path)
    assert scope_b != scope_a and public_device['id'] != device_a['id']


def test_deleted_external_exposure_cascade_is_visible_and_detachable(tmp_path,monkeypatch):
    path = tmp_path / 'review-stale-exposure.db'
    site = RemoteSensorStore(path).create_site('Exposure site')
    scope = create_scope(scope_type='PUBLIC_IPV4',canonical_target='8.8.8.8',name='Exposure',
        description='review fixture',authorized=True,enabled=True,authorization_confirmed_at=AT.isoformat(),
        authorization_confirmation_version='test',authorization_source='test',db_path=path)
    device = create_scope_device(scope['id'],first_seen=AT.isoformat(),last_seen=AT.isoformat(),
                                 status='ONLINE',db_path=path)
    with get_connection(path) as connection:
        connection.execute('INSERT INTO remote_scope_sites(scope_id,site_id,created_at) VALUES (?,?,?)',
                           (scope['id'],site['id'],AT.isoformat()))
        cursor = connection.execute('''INSERT INTO external_exposures (
            stable_key,scope_id,scope_type,canonical_target,device_id,target_ip,port_number,transport,
            service_name,product,version,extra_info,service_confidence,first_seen,last_seen,
            last_observation_source,last_scanner,created_at,updated_at)
            VALUES ('review-exposure',?,'PUBLIC_IPV4','8.8.8.8',?,'8.8.8.8',443,'tcp','https',NULL,NULL,NULL,
            NULL,?,?, 'test','test',?,?)''',
            (scope['id'],device['id'],AT.isoformat(),AT.isoformat(),AT.isoformat(),AT.isoformat()))
        exposure_id = cursor.lastrowid
        cursor = connection.execute('''INSERT INTO external_exposure_changes (
            event_key,exposure_id,scope_id,change_type,previous_value,current_value,reason,observed_at,
            source,scanner,created_at) VALUES ('review-change',?,?,'NEW_EXPOSURE',NULL,'443/tcp','review',?,
            'test','test',?)''',(exposure_id,scope['id'],AT.isoformat(),AT.isoformat()))
        change_id = cursor.lastrowid
    review = create_review(title='Stale evidence',db_path=path)
    add_evidence(review['id'],evidence_type='EXTERNAL_EXPOSURE_CHANGE',evidence_id=change_id,db_path=path)
    assert list_evidence(review['id'],db_path=path)['items'][0]['source_status'] == 'AVAILABLE'
    monkeypatch.setattr(api,'DB_PATH',path)
    with get_connection(path) as connection:
        connection.execute('DELETE FROM external_exposures WHERE id=?',(exposure_id,))
        assert connection.execute('SELECT 1 FROM external_exposure_changes WHERE id=?',(change_id,)).fetchone() is None
    with TestClient(api.app) as client:
        response = client.get(f'/incident-reviews/{review["id"]}/evidence')
        assert response.status_code == 200
        assert response.json()['items'][0]['source_status'] == 'MISSING'
        detached = client.delete(f'/incident-reviews/{review["id"]}/evidence/EXTERNAL_EXPOSURE_CHANGE/{change_id}')
        assert detached.status_code == 200
        assert client.get(f'/incident-reviews/{review["id"]}/evidence').json()['total'] == 0
    with get_connection(path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM incident_review_evidence WHERE incident_id=?',
                                  (review['id'],)).fetchone()[0] == 0
