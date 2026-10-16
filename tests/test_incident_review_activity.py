import pytest
from fastapi import FastAPI

from api.incident_reviews import register_incident_review_routes
from database.db import get_connection, initialize_database
from database.incident_reviews import IncidentReviewError, create_review
from database.inventory import create_device
from database.networks import create_network
from services.incident_review_operations import (
    ACTIVITY_EVENT_TYPES,
    build_incident_review_activity,
)


def _fixture(path):
    initialize_database(path)
    with get_connection(path) as connection:
        site_id = connection.execute(
            "INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('Current site',1,?,?)",
            ('2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00'),
        ).lastrowid
    network = create_network('10.91.0.0/24', 'activity-fixture', 'fixture', True, True, path)
    with get_connection(path) as connection:
        scope_id = connection.execute('SELECT scope_id FROM network_scope_links WHERE network_id=?',
                                      (network['id'],)).fetchone()[0]
        connection.execute('INSERT INTO remote_scope_sites (scope_id,site_id,created_at) VALUES (?,?,?)',
                           (scope_id, site_id, '2026-10-01T00:00:00+00:00'))
    device = create_device(stable_key='activity-device', network_id=network['id'], mac_address=None,
        hostname='activity-host', vendor=None, first_seen='2026-10-01T00:00:00+00:00',
        last_seen='2026-10-01T00:00:00+00:00', last_ip_address='10.91.0.1', status='ONLINE',
        identity_confidence='LOW', db_path=path)
    review = create_review(title='Current review title', site_id=site_id, scope_id=scope_id,
                           device_id=device['id'], db_path=path)
    return site_id, review['id'], scope_id, device['id']


def _event(path, review_id, kind, created_at, **values):
    fields = {
        'field_name': values.get('field_name'),
        'old_value': values.get('old_value'),
        'new_value': values.get('new_value'),
        'evidence_type': values.get('evidence_type'),
        'evidence_id': values.get('evidence_id'),
        'note_id': values.get('note_id'),
        'summary': values.get('summary', 'UNTRUSTED STORED SUMMARY'),
    }
    with get_connection(path) as connection:
        return connection.execute('''INSERT INTO incident_review_events (
            incident_review_id,event_type,actor_source,created_at,field_name,old_value,new_value,
            evidence_type,evidence_id,note_id,summary
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            (review_id, kind, 'OPERATOR', created_at, fields['field_name'], fields['old_value'],
             fields['new_value'], fields['evidence_type'], fields['evidence_id'],
             fields['note_id'], fields['summary'])).lastrowid


def test_activity_empty_shape_and_all_event_types_have_safe_rows(tmp_path):
    path = tmp_path / 'activity.db'
    initialize_database(path)
    empty = build_incident_review_activity(db_path=path)
    assert empty == {'activity': [], 'pagination': {'limit': 20, 'offset': 0, 'total': 0}}

    site_id, review_id, _, _ = _fixture(path)
    with get_connection(path) as connection:
        note_id = connection.execute('''INSERT INTO incident_review_notes
            (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)''',
            (review_id, 'PRIVATE NOTE BODY', 'OPERATOR', '2026-10-01T00:00:01+00:00')).lastrowid
    event_values = {
        'STATE_CHANGED': {'field_name': 'state', 'old_value': 'OPEN', 'new_value': 'CLOSED'},
        'PRIORITY_CHANGED': {'field_name': 'priority', 'old_value': 'MEDIUM', 'new_value': 'HIGH'},
        'CONFIDENCE_CHANGED': {'field_name': 'confidence', 'old_value': 'LOW', 'new_value': 'HIGH'},
        'DISPOSITION_CHANGED': {'field_name': 'disposition', 'old_value': 'UNREVIEWED', 'new_value': 'BENIGN'},
        'REVIEW_FIELD_CHANGED': {'field_name': 'title', 'old_value': 'PRIVATE OLD TITLE', 'new_value': 'PRIVATE NEW TITLE'},
        'FINAL_SUMMARY_CHANGED': {'field_name': None, 'old_value': 'PRIVATE SUMMARY', 'new_value': 'PRIVATE SUMMARY 2'},
        'ANALYST_NOTE_ADDED': {'field_name': 'analyst_note', 'old_value': None, 'new_value': 'PRIVATE NOTE BODY', 'note_id': note_id},
        'ANALYST_NOTE_CLEARED': {'field_name': 'analyst_note', 'old_value': 'PRIVATE NOTE BODY', 'new_value': None, 'note_id': note_id},
        'EVIDENCE_ATTACHED': {'evidence_type': 'WEB_DETECTION', 'evidence_id': 9001},
        'EVIDENCE_DETACHED': {'evidence_type': 'THREAT_DETECTION', 'evidence_id': 9002},
    }
    for index, kind in enumerate(sorted(ACTIVITY_EVENT_TYPES)):
        _event(path, review_id, kind, f'2026-10-01T00:00:{index:02d}+00:00',
               **event_values.get(kind, {}))

    result = build_incident_review_activity(db_path=path, limit=100)
    assert result['pagination']['total'] == 14  # creation event plus thirteen explicit event types
    assert {row['event_type'] for row in result['activity']} == ACTIVITY_EVENT_TYPES
    by_type = {row['event_type']: row for row in result['activity']}
    assert by_type['STATE_CHANGED']['summary'] == 'State changed from OPEN to CLOSED'
    assert by_type['PRIORITY_CHANGED']['summary'] == 'Priority changed from MEDIUM to HIGH'
    assert by_type['CONFIDENCE_CHANGED']['summary'] == 'Confidence changed from LOW to HIGH'
    assert by_type['DISPOSITION_CHANGED']['summary'] == 'Disposition changed from UNREVIEWED to BENIGN'
    assert by_type['REVIEW_FIELD_CHANGED']['summary'] == 'Review field updated'
    assert by_type['FINAL_SUMMARY_CHANGED']['summary'] == 'Final summary updated'
    assert by_type['ANALYST_NOTE_ADDED']['summary'] == 'Analyst note added'
    assert by_type['ANALYST_NOTE_CLEARED']['summary'] == 'Analyst note cleared'
    assert by_type['EVIDENCE_ATTACHED']['summary'] == 'Evidence attached'
    assert by_type['EVIDENCE_DETACHED']['summary'] == 'Evidence detached'
    assert by_type['REVIEW_CREATED']['summary'] == 'Review created'
    assert by_type['REVIEW_CLOSED']['summary'] == 'Review closed'
    assert by_type['REVIEW_REOPENED']['summary'] == 'Review reopened'
    assert by_type['REVIEW_FIELD_CHANGED']['field_name'] == 'title'
    assert by_type['ANALYST_NOTE_ADDED']['note_id'] == note_id
    assert by_type['EVIDENCE_ATTACHED']['evidence_type'] == 'WEB_DETECTION'
    assert by_type['EVIDENCE_ATTACHED']['evidence_id'] == 9001
    assert by_type['STATE_CHANGED']['field_name'] == 'state'
    assert by_type['STATE_CHANGED']['actor_source'] == 'OPERATOR'
    for row in result['activity']:
        assert set(row) == {'event_id','incident_review_id','incident_key','review_title','event_type',
            'field_name','actor_source','created_at','site_id','scope_id','device_id','site_name',
            'summary','note_id','evidence_type','evidence_id'}
        assert row['incident_key'].startswith('IR-')
        assert row['review_title'] == 'Current review title'
        assert row['site_id'] == site_id and row['site_name'] == 'Current site'
        assert 'UNTRUSTED STORED SUMMARY' not in str(row)
        assert 'PRIVATE' not in str(row)
    assert by_type['REVIEW_CREATED']['note_id'] is None
    assert by_type['REVIEW_CREATED']['evidence_type'] is None
    assert by_type['ANALYST_NOTE_ADDED']['evidence_id'] is None


@pytest.mark.parametrize('kind,old,new,fallback', [
    ('STATE_CHANGED', 'ALIEN', 'CLOSED', 'Review state changed'),
    ('STATE_CHANGED', None, 'OPEN', 'Review state changed'),
    ('PRIORITY_CHANGED', 'LOW', 'UNKNOWN', 'Review priority changed'),
    ('CONFIDENCE_CHANGED', 'LOW', 'CRITICAL', 'Review confidence changed'),
    ('DISPOSITION_CHANGED', 'UNREVIEWED', 'UNKNOWN', 'Review disposition changed'),
])
def test_activity_invalid_scalar_values_fall_back_without_exposure(tmp_path, kind, old, new, fallback):
    path = tmp_path / 'activity-invalid.db'
    _, review_id, _, _ = _fixture(path)
    _event(path, review_id, kind, '2026-10-01T00:00:02+00:00',
           old_value=old, new_value=new, summary='DO NOT LEAK')
    row = build_incident_review_activity(db_path=path, event_type=kind)['activity'][0]
    assert row['summary'] == fallback
    assert old is None or old not in row['summary']
    assert new not in row['summary']
    assert 'DO NOT LEAK' not in str(row)


def test_activity_filters_time_boundaries_order_and_read_only(tmp_path):
    path = tmp_path / 'activity-filters.db'
    site_id, review_id, scope_id, device_id = _fixture(path)
    with get_connection(path) as connection:
        site_two = connection.execute(
            "INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('Other',1,?,?)",
            ('2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00')).lastrowid
        other_id = connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,disposition,site_id,created_at,updated_at
            ) VALUES ('IR-OTHER','Other review','', 'OPEN','LOW','LOW','UNREVIEWED',?,?,?)''',
            (site_two, '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00')).lastrowid
    id_one = _event(path, review_id, 'REVIEW_CLOSED', '2026-10-02T12:00:00+00:00')
    id_two = _event(path, review_id, 'REVIEW_REOPENED', '2026-10-02T12:00:00+00:00')
    _event(path, other_id, 'PRIORITY_CHANGED', '2026-10-03T00:00:00+00:00', old_value='LOW', new_value='HIGH')
    with get_connection(path) as connection:
        before = tuple(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                       for table in ('incident_reviews','incident_review_events','incident_review_notes',
                                     'incident_review_evidence','sites','authorized_scopes','devices',
                                     'perimeter_detections','perimeter_policy_correlations',
                                     'perimeter_host_correlations','external_exposure_changes',
                                     'threat_detections','correlations','web_detections'))
    result = build_incident_review_activity(db_path=path, since='2026-10-02T12:00:00Z',
        until='2026-10-02T12:00:00+00:00', incident_review_id=review_id,
        site_id=site_id, limit=1)
    assert result['pagination'] == {'limit': 1, 'offset': 0, 'total': 2}
    assert result['activity'][0]['event_id'] == max(id_one, id_two)
    page = build_incident_review_activity(db_path=path, incident_review_id=review_id, limit=1, offset=1)
    assert page['pagination']['total'] == 3
    last_page = build_incident_review_activity(db_path=path, incident_review_id=review_id, limit=1, offset=2)
    assert {page['activity'][0]['event_id'], last_page['activity'][0]['event_id']} == {id_one, id_two}
    assert page['activity'][0]['event_id'] > last_page['activity'][0]['event_id']
    assert build_incident_review_activity(db_path=path, scope_id=scope_id)['pagination']['total'] == 3
    assert build_incident_review_activity(db_path=path, device_id=device_id)['pagination']['total'] == 3
    assert build_incident_review_activity(db_path=path, site_id=site_two)['pagination']['total'] == 1
    assert build_incident_review_activity(db_path=path, event_type='REVIEW_CLOSED')['pagination']['total'] == 1
    with get_connection(path) as connection:
        after = tuple(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                      for table in ('incident_reviews','incident_review_events','incident_review_notes',
                                    'incident_review_evidence','sites','authorized_scopes','devices',
                                    'perimeter_detections','perimeter_policy_correlations',
                                    'perimeter_host_correlations','external_exposure_changes',
                                    'threat_detections','correlations','web_detections'))
    assert before == after


def test_activity_unattributed_label_api_filters_and_validation(tmp_path):
    path = tmp_path / 'activity-api.db'
    initialize_database(path)
    review = create_review(title='Unattributed review', db_path=path)
    _event(path, review['id'], 'REVIEW_CREATED', '2026-10-01T00:00:00+00:00')
    result = build_incident_review_activity(db_path=path)
    assert result['activity'][0]['site_id'] is None
    assert result['activity'][0]['site_name'] == 'Unattributed'
    assert result['activity'][0]['scope_id'] is None and result['activity'][0]['device_id'] is None

    app = FastAPI()
    register_incident_review_routes(app, lambda: path)
    operation = next(route.endpoint for route in app.routes
                     if getattr(route, 'path', None) == '/incident-review-operations/activity')
    route_args = {'incident_review_id': None, 'site_id': None, 'scope_id': None, 'device_id': None,
                  'since': None, 'until': None, 'limit': 1, 'offset': 0}
    response = operation(event_type='REVIEW_CREATED', **route_args)
    assert response['pagination'] == {'limit': 1, 'offset': 0, 'total': 2}
    with pytest.raises(Exception) as invalid_type:
        operation(event_type='NOT_REAL', **route_args)
    assert getattr(invalid_type.value, 'status_code', None) == 422
    params = app.openapi()['paths']['/incident-review-operations/activity']['get']['parameters']
    limit_schema = next(param['schema'] for param in params if param['name'] == 'limit')
    offset_schema = next(param['schema'] for param in params if param['name'] == 'offset')
    assert (limit_schema['minimum'], limit_schema['maximum']) == (1, 100)
    assert (offset_schema['minimum'], offset_schema['maximum']) == (0, 100000)
    with pytest.raises(IncidentReviewError):
        build_incident_review_activity(db_path=path, event_type='NOT_REAL')
    for kwargs in (
        {'since': 'yesterday'}, {'since': '2026-10-01T00:00:00'},
        {'since': '2026-10-03T00:00:00Z', 'until': '2026-10-02T00:00:00Z'},
        {'incident_review_id': 0}, {'limit': 0}, {'limit': 101}, {'offset': -1}, {'offset': 100001},
    ):
        with pytest.raises(IncidentReviewError):
            build_incident_review_activity(db_path=path, **kwargs)


def test_activity_event_type_constant_matches_schema_contract():
    assert len(ACTIVITY_EVENT_TYPES) == 13


def test_activity_attribution_is_current_review_context_not_event_snapshot(tmp_path):
    path = tmp_path / 'activity-current-attribution.db'
    site_id, review_id, _, _ = _fixture(path)
    event_id = _event(path, review_id, 'REVIEW_CREATED', '2026-10-01T00:00:00+00:00')
    with get_connection(path) as connection:
        connection.execute('UPDATE incident_reviews SET site_id=NULL,scope_id=NULL,device_id=NULL WHERE id=?',
                           (review_id,))
    row = next(row for row in build_incident_review_activity(db_path=path)['activity']
               if row['event_id'] == event_id)
    assert row['site_id'] is None and row['site_name'] == 'Unattributed'
    assert row['scope_id'] is None and row['device_id'] is None
    assert row['site_id'] != site_id
