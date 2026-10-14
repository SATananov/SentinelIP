from datetime import datetime, timedelta, timezone

import pytest

import api.main as api
from database.db import get_connection, initialize_database
from database.incident_reviews import (
    IncidentReviewError, add_evidence, add_note, create_review, get_review, list_evidence,
    list_notes, list_related_evidence, list_reviews, list_timeline, remove_evidence, update_review,
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


def test_migrations_41_and_42_are_additive_idempotent_and_fk_clean(tmp_path,monkeypatch):
    path = tmp_path / 'review-migration.db'
    from database import migrations as migration_module
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS[:40])
    initialize_database(path)
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS)
    # Apply the full initialization twice, as production startup does.
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM schema_migrations WHERE version=42').fetchone()[0] == 1
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {'incident_reviews','incident_review_evidence','incident_review_events',
                'incident_review_notes','incidents','incident_correlations'} <= names
        assert max(version for version,_ in MIGRATIONS) == 42


def test_migration_42_adds_append_only_history_idempotently(tmp_path,monkeypatch):
    path = tmp_path / 'review-migration-42.db'
    from database import migrations as migration_module
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS[:41])
    initialize_database(path)
    with get_connection(path) as connection:
        cursor = connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,created_at,updated_at,
            disposition) VALUES ('IR-pre13c','Pre-13C review','','OPEN','MEDIUM','MEDIUM',
            '2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00','UNREVIEWED')''')
        legacy_review_id = cursor.lastrowid
    with get_connection(path) as connection:
        assert connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 41
        before = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 42
        after = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {'incident_review_events','incident_review_notes'} <= after - before
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert list_timeline(legacy_review_id,db_path=path)['total'] == 0


def test_review_timeline_and_notes_are_atomic_bounded_and_ordered(tmp_path):
    path = tmp_path / 'review-history.db'
    review = create_review(title='History review',db_path=path)
    assert [row['event_type'] for row in list_timeline(review['id'],db_path=path)['items']] == ['REVIEW_CREATED']
    update_review(review['id'],{'state':'IN_REVIEW','priority':'HIGH','confidence':'HIGH',
        'disposition':'NEEDS_MONITORING','title':'Updated history review','summary':'Changed'},path)
    update_review(review['id'],{'state':'CLOSED'},path)
    update_review(review['id'],{'state':'OPEN'},path)
    update_review(review['id'],{'state':'OPEN'},path)
    events = list_timeline(review['id'],limit=100,db_path=path)['items']
    types = [row['event_type'] for row in events]
    assert types.count('REVIEW_CLOSED') == 1 and types.count('REVIEW_REOPENED') == 1
    assert types.count('STATE_CHANGED') == 1
    assert types.count('PRIORITY_CHANGED') == 1 and types.count('CONFIDENCE_CHANGED') == 1
    assert types.count('DISPOSITION_CHANGED') == 1 and types.count('REVIEW_FIELD_CHANGED') == 2
    changed_fields = [row['field_name'] for row in events if row['field_name'] is not None]
    assert changed_fields[:8] == ['state','state','summary','title','disposition','confidence',
                                  'priority','state']
    count = len(events)
    update_review(review['id'],{'state':'OPEN','priority':'HIGH'},path)
    assert len(list_timeline(review['id'],db_path=path)['items']) == count
    update_review(review['id'],{'analyst_note':'Old note'},path)
    update_review(review['id'],{'analyst_note':'New note'},path)
    update_review(review['id'],{'analyst_note':None},path)
    note_events = [row['event_type'] for row in list_timeline(review['id'],db_path=path)['items']]
    assert note_events.count('ANALYST_NOTE_ADDED') == 2
    assert note_events.count('ANALYST_NOTE_CLEARED') == 1
    with pytest.raises(IncidentReviewError):
        add_note(review['id'],'   ',path)
    with pytest.raises(IncidentReviewError):
        add_note(review['id'],'x' * 4001,path)
    first = add_note(review['id'],'A factual analyst note',path)
    second = add_note(review['id'],'A second factual analyst note',path)
    assert first['note_text'] and second['id'] > first['id']
    with get_connection(path) as connection:
        with pytest.raises(Exception,match='append-only'):
            connection.execute('UPDATE incident_review_notes SET note_text=? WHERE id=?',
                               ('Changed',first['id']))
        with pytest.raises(Exception,match='append-only'):
            connection.execute('DELETE FROM incident_review_notes WHERE id=?',(first['id'],))
        event_id = connection.execute('SELECT id FROM incident_review_events WHERE incident_review_id=? LIMIT 1',
                                      (review['id'],)).fetchone()[0]
        with pytest.raises(Exception,match='append-only'):
            connection.execute('UPDATE incident_review_events SET summary=? WHERE id=?',
                               ('Changed',event_id))
    notes = list_notes(review['id'],limit=1,db_path=path)
    assert notes['total'] == 2 and notes['items'][0]['id'] == second['id']
    history = list_timeline(review['id'],limit=2,db_path=path)
    assert history['total'] > 2 and len(history['items']) == 2
    assert history['items'][0]['id'] > history['items'][1]['id']


def test_evidence_review_history_is_idempotent_and_detaches_stale_link(tmp_path):
    path = tmp_path / 'review-evidence-history.db'
    site = RemoteSensorStore(path).create_site('History site')
    source = _detection(path,site['id'],30)
    review = create_review(title='Evidence history',site_id=site['id'],db_path=path)
    add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=source['id'],db_path=path)
    add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=source['id'],db_path=path)
    with get_connection(path) as connection:
        connection.execute('DELETE FROM perimeter_detections WHERE id=?',(source['id'],))
    remove_evidence(review['id'],'PERIMETER_DETECTION',source['id'],path)
    kinds = [row['event_type'] for row in list_timeline(review['id'],db_path=path)['items']]
    assert kinds.count('EVIDENCE_ATTACHED') == 1
    assert kinds.count('EVIDENCE_DETACHED') == 1


def test_timeline_and_notes_api_are_bounded_and_review_scoped(tmp_path,monkeypatch):
    path = tmp_path / 'review-history-api.db'
    monkeypatch.setattr(api,'DB_PATH',path)
    initialize_database(path)
    review = create_review(title='History API review',db_path=path)
    routes = {route.path:route.endpoint for route in api.app.routes if hasattr(route,'endpoint')}
    add_note_route = routes['/incident-reviews/{incident_id}/notes']
    note_route = routes['/incident-reviews/{incident_id}/timeline']
    notes_route = [route.endpoint for route in api.app.routes
                   if getattr(route,'path',None)=='/incident-reviews/{incident_id}/notes'
                   and 'GET' in route.methods][0]
    from api.incident_reviews import NoteCreate
    made = add_note_route(review['id'],NoteCreate(note_text='Operator checked the available record.'))
    assert made['actor_source'] == 'OPERATOR'
    assert notes_route(review['id'],limit=1,offset=0)['total'] == 1
    assert note_route(review['id'],limit=1,offset=0)['items'][0]['event_type'] == 'ANALYST_NOTE_ADDED'
    with pytest.raises(Exception) as invalid_limit:
        note_route(review['id'],limit=101,offset=0)
    assert getattr(invalid_limit.value,'status_code',None) == 422
    for endpoint, args, kwargs in ((note_route,(999999,),{'limit':100,'offset':0}),
        (notes_route,(999999,),{'limit':100,'offset':0}),
        (add_note_route,(999999,NoteCreate(note_text='No review')),{})):
        with pytest.raises(Exception) as not_found:
            endpoint(*args,**kwargs)
        assert getattr(not_found.value,'status_code',None) == 404


def test_incident_review_offsets_are_bounded_by_api_schema_and_helpers(tmp_path):
    from typing import Annotated
    from fastapi import FastAPI, Query
    from pydantic import TypeAdapter, ValidationError
    from api.incident_reviews import register_incident_review_routes

    path = tmp_path / 'review-offset-api.db'
    initialize_database(path)
    first = create_review(title='Offset page one',db_path=path)
    create_review(title='Offset page two',db_path=path)
    add_note(first['id'],'Offset fixture',path)
    test_app = FastAPI()
    register_incident_review_routes(test_app,lambda:path)
    routes = test_app.openapi()['paths']
    for route in ('/incident-reviews','/incident-reviews/{incident_id}/evidence',
                  '/incident-reviews/{incident_id}/timeline','/incident-reviews/{incident_id}/notes'):
        params = routes[route]['get']['parameters']
        offset_schema = next(param['schema'] for param in params if param['name']=='offset')
        assert offset_schema['minimum'] == 0
        assert offset_schema['maximum'] == 100000

    offset_adapter = TypeAdapter(Annotated[int,Query(ge=0,le=100000)])
    assert offset_adapter.validate_python(0) == 0
    assert offset_adapter.validate_python(100000) == 100000
    for invalid in (100001,10**100,'9' * 200):
        with pytest.raises(ValidationError):
            offset_adapter.validate_python(invalid)
    # Endpoint pagination remains usable at both ends and after multiple rows.
    assert len(list_reviews(limit=1,offset=0,db_path=path)['items']) == 1
    assert list_reviews(limit=1,offset=100000,db_path=path)['items'] == []
    assert list_evidence(first['id'],offset=100000,db_path=path)['items'] == []
    assert list_timeline(first['id'],offset=100000,db_path=path)['items'] == []
    assert list_notes(first['id'],offset=100000,db_path=path)['items'] == []


@pytest.mark.parametrize('function,args,kwargs', [
    (list_reviews,(),{'limit':1,'offset':100001}),
    (list_evidence,(1,),{'limit':1,'offset':100001}),
    (list_reviews,(),{'limit':1,'offset':10**100}),
    (list_evidence,(1,),{'limit':1,'offset':10**100}),
])
def test_incident_review_database_helpers_reject_oversized_offsets(
        tmp_path,function,args,kwargs):
    with pytest.raises(IncidentReviewError):
        function(*args,db_path=tmp_path/'offset-helper.db',**kwargs)


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
    from api.incident_reviews import EvidenceCreate, ReviewCreate, ReviewUpdate
    routes = {(route.path,next(iter(route.methods))):route.endpoint for route in api.app.routes
              if hasattr(route,'endpoint') and route.methods}
    made = routes[('/incident-reviews','POST')](ReviewCreate(title='Analyst review',site_id=site['id'],
        priority='HIGH',confidence='MEDIUM'))
    incident_id = made['id']
    attached = routes[('/incident-reviews/{incident_id}/evidence','POST')](incident_id,
        EvidenceCreate(evidence_type='PERIMETER_DETECTION',evidence_id=source['id'],reason='Review queue'))
    assert attached['observed_at'] == before['first_seen']
    assert routes[('/incident-reviews','GET')](state='OPEN',priority='HIGH',site_id=None,
        scope_id=None,device_id=None,disposition=None,limit=20,offset=0)['total'] == 1
    changed = routes[('/incident-reviews/{incident_id}','PATCH')](incident_id,
        ReviewUpdate(state='CLOSED',disposition='NEEDS_MONITORING',analyst_note='Check next week'))
    assert changed['closed_at']
    assert routes[('/incident-reviews/{incident_id}/evidence','GET')](incident_id,limit=100,offset=0)['total'] == 1
    with pytest.raises(Exception) as invalid_type:
        routes[('/incident-reviews/{incident_id}/evidence/{evidence_type}/{evidence_id}','DELETE')](incident_id,'FAKE',1)
    assert getattr(invalid_type.value,'status_code',None) == 422
    assert routes[('/incident-reviews/{incident_id}/evidence/{evidence_type}/{evidence_id}','DELETE')](
        incident_id,'PERIMETER_DETECTION',source['id']) == {'removed':True}
    assert get_perimeter_detection(source['id'],path) == before
    with pytest.raises(Exception) as missing_source:
        routes[('/incident-reviews/{incident_id}/evidence','POST')](incident_id,
            EvidenceCreate(evidence_type='PERIMETER_DETECTION',evidence_id=999999))
    assert getattr(missing_source.value,'status_code',None) == 404
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ReviewCreate(title='bad',table='events')


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
    routes = {(route.path,next(iter(route.methods))):route.endpoint for route in api.app.routes
              if hasattr(route,'endpoint') and route.methods}
    read_evidence = routes[('/incident-reviews/{incident_id}/evidence','GET')]
    assert read_evidence(review['id'],limit=100,offset=0)['items'][0]['source_status'] == 'MISSING'
    detached = routes[('/incident-reviews/{incident_id}/evidence/{evidence_type}/{evidence_id}','DELETE')](
        review['id'],'EXTERNAL_EXPOSURE_CHANGE',change_id)
    assert detached == {'removed':True}
    assert read_evidence(review['id'],limit=100,offset=0)['total'] == 0
    with get_connection(path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM incident_review_evidence WHERE incident_id=?',
                                  (review['id'],)).fetchone()[0] == 0


def _insert_review_threat(path, device_id, observed_at, stable_key):
    at = observed_at.isoformat()
    with get_connection(path) as connection:
        cursor = connection.execute('''INSERT INTO threat_detections (
            stable_key,threat_type,state,severity,confidence,device_id,source_ip,sensor_id,hostname,
            primary_evidence_type,primary_evidence_id,anchor_id,reason,recommendation,rule_id,rule_version,
            first_seen,last_seen,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (stable_key,'SUSPICIOUS_AUTH_ACTIVITY','ANOMALOUS','LOW','MEDIUM',device_id,
             '203.0.113.20',None,None,'SSH_EVENT',1,1,'review signal','review evidence',
             'review.test','1',at,at,at,at))
        return cursor.lastrowid


def _linked_threat_review(path, *, attribution='site'):
    site,scope,device = _private_device(path,'Related','192.168.70.0/24')
    threat_id = _insert_review_threat(path,device['id'],AT,'related-anchor')
    review_attribution = {'site_id':site['id']}
    if attribution == 'scope':
        review_attribution = {'scope_id':scope}
    elif attribution == 'device':
        review_attribution = {'site_id':site['id'],'scope_id':scope,'device_id':device['id']}
    elif attribution != 'site':
        raise AssertionError('Unsupported review fixture attribution.')
    review = create_review(title='Related evidence review',**review_attribution,db_path=path)
    add_evidence(review['id'],evidence_type='THREAT_DETECTION',evidence_id=threat_id,db_path=path)
    return site,scope,device,threat_id,review


def test_related_evidence_exact_device_scope_and_site_matches(tmp_path):
    path = tmp_path / 'related-match.db'
    site,scope,device,anchor,review = _linked_threat_review(path,attribution='device')
    device_candidate = _insert_review_threat(path,device['id'],AT+timedelta(minutes=1),'device-candidate')
    exact_device = list_related_evidence(review['id'],db_path=path)
    device_item = next(item for item in exact_device['items'] if item['evidence_id']==device_candidate)
    assert device_item['match_reason'] == 'Same device within review time window'

    # A scope-only review matches through the unique device-to-scope relationship.
    scope_review = create_review(title='Scope review',scope_id=scope,db_path=path)
    add_evidence(scope_review['id'],evidence_type='THREAT_DETECTION',evidence_id=anchor,db_path=path)
    scope_candidate = _insert_review_threat(path,device['id'],AT+timedelta(minutes=2),'scope-candidate')
    scope_item = next(item for item in list_related_evidence(scope_review['id'],db_path=path)['items']
                      if item['evidence_id']==scope_candidate)
    assert scope_item['match_reason'] == 'Same scope within review time window'

    # A site-only review can match a device source only through its unique
    # authorized-scope/site relationship.
    site_review = create_review(title='Site review',site_id=site['id'],db_path=path)
    add_evidence(site_review['id'],evidence_type='THREAT_DETECTION',evidence_id=anchor,db_path=path)
    site_candidate = _insert_review_threat(path,device['id'],AT+timedelta(minutes=3),'site-candidate')
    site_item = next(item for item in list_related_evidence(site_review['id'],db_path=path)['items']
                     if item['evidence_id']==site_candidate)
    assert site_item['match_reason'] == 'Same site within review time window'


def test_related_evidence_no_wildcards_and_ambiguous_device_scope_is_excluded(tmp_path,monkeypatch):
    path = tmp_path / 'related-fail-closed.db'
    site,scope,device,anchor,review = _linked_threat_review(path,attribution='device')
    # This site-only source has no device attribution; shared site cannot
    # fill the missing device field required by the review.
    perimeter = _detection(path,site['id'],6)
    results = list_related_evidence(review['id'],db_path=path)['items']
    assert not any(item['evidence_type']=='PERIMETER_DETECTION' and item['evidence_id']==perimeter['id']
                   for item in results)

    ambiguous_review = create_review(title='Ambiguous scope review',scope_id=scope,db_path=path)
    add_evidence(ambiguous_review['id'],evidence_type='THREAT_DETECTION',
                 evidence_id=anchor,db_path=path)
    update_review(ambiguous_review['id'],{'site_id':site['id']},path)
    # Force the existing device-to-scope resolver to report ambiguity; its
    # fail-closed path must not turn a device-only source into a scope match.
    import database.incident_reviews as review_db
    monkeypatch.setattr(review_db,'_device_scope_ids',lambda _connection,_device:{scope,scope+1})
    ambiguous_candidate = _insert_review_threat(path,device['id'],AT+timedelta(minutes=4),'ambiguous-candidate')
    assert not any(item['evidence_id']==ambiguous_candidate
                   for item in list_related_evidence(ambiguous_review['id'],db_path=path)['items'])


def test_related_evidence_time_boundaries_order_and_linked_state(tmp_path):
    path = tmp_path / 'related-window.db'
    site,scope,device,anchor,review = _linked_threat_review(path,attribution='device')
    at_start = _insert_review_threat(path,device['id'],AT-timedelta(minutes=30),'at-start')
    at_end = _insert_review_threat(path,device['id'],AT+timedelta(minutes=30),'at-end')
    outside = _insert_review_threat(path,device['id'],AT+timedelta(minutes=30,seconds=1),'outside')
    same_time_b = _insert_review_threat(path,device['id'],AT+timedelta(minutes=5),'same-b')
    same_time_a = _insert_review_threat(path,device['id'],AT+timedelta(minutes=5),'same-a')
    offset_equivalent = _insert_review_threat(
        path,device['id'],AT.astimezone(timezone(timedelta(hours=2))),'offset-equivalent')
    naive_utc = _insert_review_threat(path,device['id'],AT.replace(tzinfo=None),'naive-utc')
    result = list_related_evidence(review['id'],db_path=path)
    ids = [item['evidence_id'] for item in result['items']]
    assert at_start in ids and at_end in ids and outside not in ids
    assert offset_equivalent in ids and naive_utc in ids
    assert result['items'][0]['evidence_id'] == at_end
    linked = next(item for item in result['items'] if item['evidence_id']==anchor)
    assert linked['already_linked'] is True
    tied = [item['evidence_id'] for item in result['items'] if item['observed_at']==(AT+timedelta(minutes=5)).isoformat()]
    assert tied == sorted(tied)
    assert same_time_a in tied and same_time_b in tied


def test_related_evidence_no_anchor_missing_source_limit_and_filter(tmp_path):
    path = tmp_path / 'related-bounds.db'
    site,scope,device,anchor,review = _linked_threat_review(path,attribution='device')
    no_anchor = create_review(title='No time anchor',device_id=device['id'],db_path=path)
    assert list_related_evidence(no_anchor['id'],db_path=path)['items'] == []
    missing = _insert_review_threat(path,device['id'],AT+timedelta(minutes=1),'missing-source')
    add_evidence(review['id'],evidence_type='THREAT_DETECTION',evidence_id=missing,db_path=path)
    with get_connection(path) as connection:
        connection.execute('DELETE FROM threat_detections WHERE id=?',(missing,))
    # A stale 13A link stays visible, but cannot become an attachable suggestion.
    assert any(item['evidence_id']==missing and item['source_status']=='MISSING'
               for item in list_evidence(review['id'],db_path=path)['items'])
    assert missing not in [item['evidence_id'] for item in list_related_evidence(review['id'],db_path=path)['items']]
    candidate_ids = [_insert_review_threat(path,device['id'],AT+timedelta(minutes=10),f'limited-{i}') for i in range(105)]
    assert len(list_related_evidence(review['id'],limit=100,db_path=path)['items']) == 100
    filtered = list_related_evidence(review['id'],limit=5,evidence_type='THREAT_DETECTION',db_path=path)
    assert len(filtered['items']) == 5 and filtered['total'] == 100
    with pytest.raises(IncidentReviewError):
        list_related_evidence(review['id'],evidence_type='devices',db_path=path)
    assert all(item['evidence_type']=='THREAT_DETECTION' for item in filtered['items'])
    assert candidate_ids[0] in [item['evidence_id'] for item in list_related_evidence(review['id'],db_path=path)['items']]


def test_related_evidence_api_is_read_only_strict_and_legacy_incidents_unchanged(tmp_path,monkeypatch):
    path = tmp_path / 'related-api.db'
    initialize_database(path)
    monkeypatch.setattr(api,'DB_PATH',path)
    site,scope,device,anchor,review = _linked_threat_review(path)
    with get_connection(path) as connection:
        before = (connection.execute('SELECT updated_at FROM incident_reviews WHERE id=?',(review['id'],)).fetchone()[0],
            connection.execute('SELECT COUNT(*) FROM incident_review_evidence').fetchone()[0],
            connection.execute('SELECT COUNT(*) FROM threat_detections').fetchone()[0])
    routes = {route.path:route.endpoint for route in api.app.routes if hasattr(route,'endpoint')}
    related_route = routes['/incident-reviews/{incident_id}/related-evidence']
    body = related_route(review['id'],limit=100)
    assert set(body['items'][0]) == {'evidence_type','evidence_id','observed_at','source_status','already_linked','match_reason'}
    assert body['items'][0]['source_status'] == 'AVAILABLE'
    route_schema = api.app.openapi()['paths']['/incident-reviews/{incident_id}/related-evidence']['get']
    parameters = {item['name']:item for item in route_schema['parameters']}
    assert parameters['limit']['schema']['minimum'] == 1
    assert parameters['limit']['schema']['maximum'] == 100
    assert set(parameters['evidence_type']['schema']['anyOf'][0]['enum']) == {
        'PERIMETER_DETECTION','PERIMETER_POLICY_CORRELATION','PERIMETER_HOST_CORRELATION',
        'EXTERNAL_EXPOSURE_CHANGE','THREAT_DETECTION','THREAT_CORRELATION','WEB_DETECTION',
    }
    with pytest.raises(ValueError):
        list_related_evidence(review['id'],limit=101,db_path=path)
    with pytest.raises(ValueError):
        list_related_evidence(review['id'],evidence_type='unknown',db_path=path)
    legacy_route = routes['/incidents']
    legacy_before = legacy_route(limit=20,offset=0)
    assert legacy_before['total'] == 0
    wrong_site = RemoteSensorStore(path).create_site('Wrong site')
    foreign = _detection(path,wrong_site['id'],8)
    with pytest.raises(IncidentReviewError):
        add_evidence(review['id'],evidence_type='PERIMETER_DETECTION',evidence_id=foreign['id'],db_path=path)
    assert legacy_route(limit=20,offset=0) == legacy_before
    with get_connection(path) as connection:
        after = (connection.execute('SELECT updated_at FROM incident_reviews WHERE id=?',(review['id'],)).fetchone()[0],
            connection.execute('SELECT COUNT(*) FROM incident_review_evidence').fetchone()[0],
            connection.execute('SELECT COUNT(*) FROM threat_detections').fetchone()[0])
    assert after == before
