from datetime import datetime, timedelta, timezone
import sqlite3

import pytest
from fastapi import HTTPException

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
from services.incident_review_operations import (
    build_incident_review_operations, build_incident_review_site_workload,
)
from services.incident_review_operations import SIGNAL_ORDER

AT = datetime(2026, 10, 13, 11, 0, tzinfo=timezone.utc)


def test_incident_review_operations_summary_queue_filters_and_is_read_only(tmp_path):
    path = tmp_path / 'review-operations.db'
    initialize_database(path)
    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
    empty = build_incident_review_operations(db_path=path, now=now)
    assert empty['summary']['total_reviews'] == 0
    assert empty['summary']['reviews_needing_attention'] == 0
    assert empty['summary']['signal_distribution'] == {code: 0 for code in SIGNAL_ORDER}
    assert empty['summary']['priority_distribution'] == {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    assert empty['summary']['active_age_buckets'] == {key: 0 for key in ('LT_1H','H1_24','D1_3','D3_7','GT_7D')}

    fresh = create_review(title='Fresh workload', priority='CRITICAL', db_path=path)
    medium = create_review(title='Older workload', priority='MEDIUM', db_path=path)
    with get_connection(path) as connection:
        cursor = connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,created_at,updated_at,
            closed_at,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)''',
            ('IR-legacy-closed','Legacy closed','','CLOSED','LOW','LOW',
             (now-timedelta(days=8)).isoformat(),(now-timedelta(days=1)).isoformat(),
             (now-timedelta(hours=1)).isoformat(),'BENIGN'))
        closed = {'id': cursor.lastrowid}
    with get_connection(path) as connection:
        connection.execute("UPDATE incident_reviews SET created_at=?,updated_at=? WHERE id=?",
                           ((now-timedelta(days=2)).isoformat(),(now-timedelta(days=2)).isoformat(),medium['id']))
        connection.execute("UPDATE incident_reviews SET state='CLOSED',closed_at=?,created_at=?,updated_at=? WHERE id=?",
                           ((now-timedelta(hours=1)).isoformat(),(now-timedelta(days=8)).isoformat(),
                            (now-timedelta(days=1)).isoformat(),closed['id']))
        connection.execute("INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)",
                           (medium['id'],'A note','OPERATOR',(now-timedelta(hours=3)).isoformat()))
        connection.execute("INSERT INTO incident_review_events (incident_review_id,event_type,actor_source,created_at,summary) VALUES (?,?,?,?,?)",
                           (fresh['id'],'REVIEW_CREATED','OPERATOR',(now-timedelta(minutes=5)).isoformat(),'Created'))
    result = build_incident_review_operations(db_path=path, now=now, sort='priority')
    assert result['summary']['total_reviews'] == 3
    assert result['summary']['open_count'] == 2 and result['summary']['closed_count'] == 1
    assert result['summary']['unresolved_count'] == 2
    assert result['summary']['priority_distribution']['LOW'] == 1
    assert result['summary']['disposition_distribution']['UNREVIEWED'] == 2
    assert result['summary']['active_age_buckets']['D1_3'] == 1
    rows = {row['id']: row for row in result['queue']}
    assert rows[medium['id']]['note_count'] == 1
    assert rows[medium['id']]['latest_activity_at'] == (now-timedelta(hours=3)).isoformat()
    assert rows[medium['id']]['age_bucket'] == 'D1_3'
    assert rows[closed['id']]['age_seconds'] is None and rows[closed['id']]['age_bucket'] is None
    assert rows[closed['id']]['latest_activity_at'] == rows[closed['id']]['updated_at']
    assert rows[fresh['id']]['has_final_summary'] == 0
    assert [row['priority'] for row in result['queue']] == ['CRITICAL','MEDIUM','LOW']
    assert build_incident_review_operations(db_path=path, now=now, has_evidence=False)['pagination']['total'] == 3
    assert build_incident_review_operations(db_path=path, now=now, age_bucket='D1_3')['pagination']['total'] == 1
    assert build_incident_review_operations(db_path=path, now=now, unresolved_only=True)['pagination']['total'] == 2
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, now=now, unresolved_only=True, state='CLOSED')
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, now=now, sort='created_at')
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, now=now, age_bucket='INVALID')
    plan = build_incident_review_operations(db_path=path, now=now, explain=True)['summary']['query_plan']
    assert plan


def test_incident_review_site_workload_groups_attention_activity_and_sorts(tmp_path):
    path = tmp_path / 'review-site-workload.db'
    initialize_database(path)
    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
    with get_connection(path) as connection:
        site_a = connection.execute("INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('Alpha',1,?,?)", (now.isoformat(), now.isoformat())).lastrowid
        site_b = connection.execute("INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('Beta',1,?,?)", (now.isoformat(), now.isoformat())).lastrowid
        site_c = connection.execute("INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('Gamma',1,?,?)", (now.isoformat(), now.isoformat())).lastrowid
    with get_connection(path) as connection:
        def raw_review(key, title, state, priority, site_id, created, updated, closed_at=None):
            return connection.execute("""INSERT INTO incident_reviews (
                incident_key,title,summary,state,priority,confidence,site_id,created_at,updated_at,closed_at,disposition
                ) VALUES (?,?, '', ?,?,'MEDIUM',?,?,?,?, 'UNREVIEWED')""",
                (key,title,state,priority,site_id,created.isoformat(),updated.isoformat(),closed_at.isoformat() if closed_at else None)).lastrowid
        active_id = raw_review('IR-site-active','Old high priority','OPEN','HIGH',site_a,now-timedelta(days=4),now-timedelta(days=4))
        raw_review('IR-site-closed','Closed','CLOSED','LOW',site_a,now-timedelta(days=5),now-timedelta(hours=2),now)
        other_id = raw_review('IR-site-other','Other site','OPEN','LOW',site_b,now,now-timedelta(days=1))
        raw_review('IR-site-closed-only','Closed-only site','CLOSED','LOW',site_c,now-timedelta(days=2),now-timedelta(days=1),now)
        unattributed_id = raw_review('IR-site-unattributed','Unattributed','OPEN','LOW',None,now-timedelta(hours=1),now-timedelta(minutes=30))
        connection.execute("INSERT INTO incident_review_events (incident_review_id,event_type,actor_source,created_at,summary) VALUES (?,?,?,?,?)", (active_id,'REVIEW_CREATED','OPERATOR',(now-timedelta(hours=1)).isoformat(),'Created'))
        connection.execute("INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)", (other_id,'Recent note','OPERATOR',(now-timedelta(minutes=2)).isoformat()))

    result = build_incident_review_site_workload(db_path=path, now=now, explain=True)
    assert set(result) == {'sites', 'pagination', 'query_plan'}
    assert result['pagination'] == {'limit': 20, 'offset': 0, 'total': 4}
    assert result['query_plan']
    rows = {row['site_id']: row for row in result['sites']}
    assert set(result['sites'][0]) == {
        'site_id','site_name','total_reviews','unresolved_reviews','open_reviews',
        'in_review_reviews','closed_reviews','reviews_needing_attention',
        'high_priority_unresolved','oldest_active_created_at',
        'oldest_active_age_seconds','latest_review_activity_at',
    }
    assert rows[site_a]['site_name'] == 'Alpha'
    assert rows[site_a]['total_reviews'] == 2
    assert rows[site_a]['open_reviews'] == 1 and rows[site_a]['closed_reviews'] == 1
    assert rows[site_a]['unresolved_reviews'] == 1
    assert rows[site_a]['reviews_needing_attention'] == 1
    assert rows[site_a]['high_priority_unresolved'] == 1
    assert rows[site_a]['oldest_active_created_at'] == (now-timedelta(days=4)).isoformat()
    assert rows[site_a]['oldest_active_age_seconds'] == 4*86400
    assert rows[site_a]['latest_review_activity_at'] == (now-timedelta(hours=1)).isoformat()
    assert rows[site_b]['in_review_reviews'] == 0
    assert rows[site_b]['oldest_active_age_seconds'] == 0
    assert rows[site_b]['latest_review_activity_at'] == (now-timedelta(minutes=2)).isoformat()
    assert rows[site_c]['oldest_active_created_at'] is None
    assert rows[site_c]['oldest_active_age_seconds'] is None
    assert rows[None]['latest_review_activity_at'] == (now-timedelta(minutes=30)).isoformat()
    assert rows[None]['site_name'] == 'Unattributed'
    assert rows[None]['total_reviews'] == 1
    assert [row['site_id'] for row in build_incident_review_site_workload(db_path=path, now=now, sort='site_name')['sites']] == [site_a, site_b, site_c, None]
    assert [row['site_id'] for row in build_incident_review_site_workload(db_path=path, now=now, sort='attention_desc')['sites']][0] == site_a
    assert [row['site_id'] for row in build_incident_review_site_workload(db_path=path, now=now, sort='oldest_active')['sites']][0] == site_a
    assert [row['site_id'] for row in build_incident_review_site_workload(db_path=path, now=now, sort='recent_activity')['sites']][0] == site_b
    assert build_incident_review_site_workload(db_path=path, now=now, limit=1, offset=1)['pagination']['total'] == 4
    assert build_incident_review_site_workload(db_path=path, now=now, limit=1, offset=1)['sites'][0]['site_id'] == site_b
    with pytest.raises(IncidentReviewError):
        build_incident_review_site_workload(db_path=path, sort='created_at')
    with pytest.raises(IncidentReviewError):
        build_incident_review_site_workload(db_path=path, limit=101)


def test_unattributed_queue_filter_is_explicit_and_conflicts_with_site_id(tmp_path):
    path = tmp_path / 'review-unattributed-filter.db'
    initialize_database(path)
    with get_connection(path) as connection:
        site_id = connection.execute("INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('Site',1,?,?)", (AT.isoformat(), AT.isoformat())).lastrowid
    create_review(title='Attributed', site_id=site_id, db_path=path)
    create_review(title='Unattributed', db_path=path)
    selected = build_incident_review_operations(db_path=path, unattributed_only=True)
    assert selected['pagination']['total'] == 1
    assert selected['queue'][0]['site_id'] is None
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, site_id=site_id, unattributed_only=True)


def test_site_workload_api_shape_and_unattributed_queue_parameter(tmp_path, monkeypatch):
    path = tmp_path / 'review-site-api.db'
    initialize_database(path)
    monkeypatch.setattr(api, 'DB_PATH', path)
    routes = {(route.path, method): route.endpoint for route in api.app.routes
              if hasattr(route, 'endpoint') for method in getattr(route, 'methods', ())}
    with get_connection(path) as connection:
        tables = ('incident_reviews','incident_review_evidence','incident_review_events',
                  'incident_review_notes','sites','authorized_scopes','devices')
        before = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in tables}
    result = routes[('/incident-review-operations/sites', 'GET')](sort='site_name', limit=10, offset=0)
    assert result == {'sites': [], 'pagination': {'limit': 10, 'offset': 0, 'total': 0}}
    with get_connection(path) as connection:
        after = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in tables}
    assert after == before
    with pytest.raises(HTTPException):
        routes[('/incident-review-operations/sites', 'GET')](sort='created_at', limit=10, offset=0)
    with pytest.raises(HTTPException):
        routes[('/incident-review-operations', 'GET')](
            state=None, priority=None, disposition=None, site_id=1, scope_id=None,
            device_id=None, has_evidence=None, age_bucket=None, unresolved_only=False,
            has_attention=None, attention_signal=None, unattributed_only=True,
            sort='newest', limit=20, offset=0)


def test_incident_review_operations_api_shape_and_get_does_not_mutate(tmp_path, monkeypatch):
    path = tmp_path / 'review-operations-api.db'
    initialize_database(path)
    monkeypatch.setattr(api, 'DB_PATH', path)
    review = create_review(title='Read-only operations', db_path=path)
    with get_connection(path) as connection:
        before = (connection.execute('SELECT COUNT(*) FROM incident_reviews').fetchone()[0],
                  connection.execute('SELECT COUNT(*) FROM incident_review_events').fetchone()[0],
                  connection.execute('SELECT COUNT(*) FROM incident_review_evidence').fetchone()[0],
                  connection.execute('SELECT COUNT(*) FROM threat_detections').fetchone()[0])
    routes = {(route.path, method): route.endpoint for route in api.app.routes
              if hasattr(route, 'endpoint') for method in getattr(route, 'methods', ())}
    response = routes[('/incident-review-operations','GET')](
        state=None, priority=None, disposition=None, site_id=None, scope_id=None,
        device_id=None, has_evidence=None, age_bucket=None, unresolved_only=False,
        has_attention=None, attention_signal=None, sort='newest', limit=20, offset=0)
    assert set(response) == {'summary', 'queue', 'pagination'}
    assert set(response['queue'][0]) == {
        'id','incident_key','title','state','priority','confidence','disposition',
        'site_id','scope_id','device_id','created_at','updated_at','first_evidence_at',
        'last_evidence_at','closed_at','has_final_summary','linked_evidence_count',
        'note_count','latest_activity_at','age_seconds','age_bucket','attention_signals',
        'attention_signal_count','has_attention',
    }
    assert response['queue'][0]['id'] == review['id']
    assert response['queue'][0]['has_attention'] is True
    assert response['queue'][0]['attention_signals'][-1]['code'] == 'NO_LINKED_EVIDENCE'
    filtered = routes[('/incident-review-operations','GET')](
        state=None, priority=None, disposition=None, site_id=None, scope_id=None,
        device_id=None, has_evidence=None, age_bucket=None, unresolved_only=False,
        has_attention=True, attention_signal='NO_LINKED_EVIDENCE',
        sort='newest', limit=20, offset=0)
    assert filtered['pagination']['total'] == 1
    with pytest.raises(HTTPException):
        routes[('/incident-review-operations','GET')](
            state=None, priority=None, disposition=None, site_id=None, scope_id=None,
            device_id=None, has_evidence=None, age_bucket=None, unresolved_only=False,
            has_attention=False, attention_signal='NO_LINKED_EVIDENCE',
            sort='newest', limit=20, offset=0)
    assert response['pagination'] == {'total': 1, 'limit': 20, 'offset': 0}
    assert routes[('/incident-reviews','GET')](state=None, priority=None, site_id=None,
        scope_id=None, device_id=None, disposition=None, limit=20, offset=0)['total'] == 1
    with get_connection(path) as connection:
        after = (connection.execute('SELECT COUNT(*) FROM incident_reviews').fetchone()[0],
                 connection.execute('SELECT COUNT(*) FROM incident_review_events').fetchone()[0],
                 connection.execute('SELECT COUNT(*) FROM incident_review_evidence').fetchone()[0],
                 connection.execute('SELECT COUNT(*) FROM threat_detections').fetchone()[0])
    assert after == before


def test_incident_review_operations_attention_signals_filters_and_read_only(tmp_path):
    path = tmp_path / 'review-operations-attention.db'
    initialize_database(path)
    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
    now_text = now.isoformat()

    def raw_review(key, *, state='OPEN', priority='LOW', created=now, updated=now,
                   closed=None, disposition='UNREVIEWED', site_id=None):
        with get_connection(path) as connection:
            cursor = connection.execute('''INSERT INTO incident_reviews (
                incident_key,title,summary,state,priority,confidence,created_at,updated_at,
                closed_at,disposition,site_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (key,key,'',state,priority,'MEDIUM',created.isoformat(),updated.isoformat(),
                 closed.isoformat() if closed else None,disposition,site_id))
            return cursor.lastrowid

    def event(review_id, event_type, at):
        with get_connection(path) as connection:
            connection.execute('''INSERT INTO incident_review_events
                (incident_review_id,event_type,actor_source,created_at) VALUES (?,?,?,?)''',
                (review_id,event_type,'OPERATOR',at.isoformat()))

    site = RemoteSensorStore(path).create_site('Signal source site')
    available_source = _detection(path,site['id'],40)
    clean = raw_review('clean', created=now-timedelta(hours=2), site_id=site['id'])
    event(clean,'REVIEW_CREATED',now-timedelta(hours=2))
    exactly_day = raw_review('exact-day', priority='HIGH', created=now-timedelta(days=1))
    event(exactly_day,'REVIEW_CREATED',now-timedelta(hours=1))
    below_day = raw_review('below-day', created=now-timedelta(hours=23, seconds=59))
    event(below_day,'REVIEW_CREATED',now-timedelta(hours=1))
    exactly_week = raw_review('exact-week', created=now-timedelta(days=8), updated=now-timedelta(days=7))
    recent_note = raw_review('recent-note', created=now-timedelta(days=8), updated=now-timedelta(days=8))
    event(recent_note,'REVIEW_CREATED',now-timedelta(days=8))
    recent_event = raw_review('recent-event', created=now-timedelta(days=8), updated=now-timedelta(days=8))
    event(recent_event,'REVIEW_CREATED',now-timedelta(days=6))
    with get_connection(path) as connection:
        connection.execute('''INSERT INTO incident_review_notes
            (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)''',
            (recent_note,'Recent note','OPERATOR',(now-timedelta(days=6)).isoformat()))
    reopened = raw_review('reopened', priority='CRITICAL', created=now-timedelta(days=8))
    event(reopened,'REVIEW_CLOSED',now-timedelta(days=6))
    event(reopened,'REVIEW_REOPENED',now-timedelta(days=5))
    tie_reopened = raw_review('tie-reopened', created=now-timedelta(hours=1))
    event(tie_reopened,'REVIEW_CLOSED',now-timedelta(hours=1))
    event(tie_reopened,'REVIEW_REOPENED',now-timedelta(hours=1))
    tie_closed = raw_review('tie-closed', created=now-timedelta(hours=1))
    event(tie_closed,'REVIEW_REOPENED',now-timedelta(hours=1))
    event(tie_closed,'REVIEW_CLOSED',now-timedelta(hours=1))
    closed_high = raw_review('closed-high', state='CLOSED', priority='CRITICAL',
        created=now-timedelta(days=10), closed=now-timedelta(days=1))
    event(closed_high,'REVIEW_REOPENED',now-timedelta(hours=1))
    event(closed_high,'REVIEW_CLOSED',now)
    missing = raw_review('missing', priority='HIGH', created=now-timedelta(days=8))
    event(missing,'REVIEW_CLOSED',now-timedelta(days=6))
    event(missing,'REVIEW_REOPENED',now-timedelta(days=5))
    with get_connection(path) as connection:
        connection.execute('''INSERT INTO incident_review_evidence
            (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,?,?,?,?)''',
            (clean,'PERIMETER_DETECTION',available_source['id'],now_text,now_text))
        connection.execute('''INSERT INTO incident_review_evidence
            (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,?,?,?,?)''',
            (missing,'THREAT_DETECTION',987654,now_text,now_text))
        connection.execute('''INSERT INTO incident_review_evidence
            (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,?,?,?,?)''',
            (reopened,'THREAT_DETECTION',987655,now_text,now_text))

    before = {}
    with get_connection(path) as connection:
        connection.row_factory = sqlite3.Row
        before = {row['id']: (row['state'],row['priority'],row['confidence'],row['disposition'])
                  for row in connection.execute('SELECT * FROM incident_reviews')}
        evidence_before = connection.execute('SELECT COUNT(*) FROM incident_review_evidence').fetchone()[0]
    result = build_incident_review_operations(db_path=path, now=now)
    by_id = {row['id']: row for row in result['queue']}
    assert by_id[clean]['attention_signals'] == []
    assert by_id[exactly_day]['attention_signals'][0]['code'] == 'HIGH_PRIORITY_UNRESOLVED'
    assert 'AGING_REVIEW' in [s['code'] for s in by_id[exactly_day]['attention_signals']]
    assert 'AGING_REVIEW' not in [s['code'] for s in by_id[below_day]['attention_signals']]
    assert 'HIGH_PRIORITY_UNRESOLVED' in [s['code'] for s in by_id[exactly_day]['attention_signals']]
    assert 'NO_RECENT_ACTIVITY' in [s['code'] for s in by_id[exactly_week]['attention_signals']]
    assert 'NO_RECENT_ACTIVITY' not in [s['code'] for s in by_id[recent_note]['attention_signals']]
    assert 'NO_RECENT_ACTIVITY' not in [s['code'] for s in by_id[recent_event]['attention_signals']]
    assert 'REOPENED_REVIEW' in [s['code'] for s in by_id[reopened]['attention_signals']]
    assert 'HIGH_PRIORITY_UNRESOLVED' in [s['code'] for s in by_id[reopened]['attention_signals']]
    assert 'REOPENED_REVIEW' in [s['code'] for s in by_id[tie_reopened]['attention_signals']]
    assert 'REOPENED_REVIEW' not in [s['code'] for s in by_id[tie_closed]['attention_signals']]
    assert by_id[closed_high]['attention_signals'] == []
    assert 'MISSING_SOURCE_EVIDENCE' in [s['code'] for s in by_id[missing]['attention_signals']]
    assert 'NO_LINKED_EVIDENCE' not in [s['code'] for s in by_id[missing]['attention_signals']]
    assert 'NO_LINKED_EVIDENCE' in [s['code'] for s in by_id[below_day]['attention_signals']]
    codes = [s['code'] for s in by_id[missing]['attention_signals']]
    assert codes == [code for code in SIGNAL_ORDER if code in codes]
    assert len(codes) == len(set(codes)) <= 6
    assert all(set(signal) == {'code','label','reason'} for signal in by_id[missing]['attention_signals'])
    assert by_id[missing]['attention_signal_count'] == len(codes)
    assert by_id[missing]['has_attention'] is True
    assert result['summary']['signal_distribution']['AGING_REVIEW'] >= 1
    assert result['summary']['reviews_needing_attention'] == sum(
        row['state'] != 'CLOSED' and row['has_attention'] for row in result['queue'])
    assert by_id[closed_high]['has_attention'] is False
    assert build_incident_review_operations(db_path=path, now=now, has_attention=True)['pagination']['total'] == result['summary']['reviews_needing_attention']
    assert build_incident_review_operations(db_path=path, now=now, has_attention=False)['pagination']['total'] == len([r for r in result['queue'] if not r['has_attention']])
    assert build_incident_review_operations(db_path=path, now=now, attention_signal='REOPENED_REVIEW')['pagination']['total'] == 3
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, now=now, has_attention=False, attention_signal='AGING_REVIEW')
    with get_connection(path) as connection:
        connection.row_factory = sqlite3.Row
        after = {row['id']: (row['state'],row['priority'],row['confidence'],row['disposition'])
                 for row in connection.execute('SELECT * FROM incident_reviews')}
        assert connection.execute('SELECT COUNT(*) FROM incident_review_evidence').fetchone()[0] == evidence_before
    assert after == before


def test_incident_review_operations_active_age_buckets_all_boundaries(tmp_path):
    path = tmp_path / 'review-operations-age.db'
    initialize_database(path)
    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
    cases = [('LT_1H',timedelta(minutes=10)),('H1_24',timedelta(hours=3)),
             ('D1_3',timedelta(days=2)),('D3_7',timedelta(days=5)),
             ('GT_7D',timedelta(days=8))]
    for index, (_, age) in enumerate(cases):
        review = create_review(title=f'Age bucket {index}', db_path=path)
        created = (now-age).isoformat()
        with get_connection(path) as connection:
            connection.execute('UPDATE incident_reviews SET created_at=? WHERE id=?',(created,review['id']))
    result = build_incident_review_operations(db_path=path, now=now)
    assert result['summary']['active_age_buckets'] == {key: 1 for key, _ in cases}


def test_incident_review_operations_filter_sort_and_pagination_allowlists(tmp_path):
    path = tmp_path / 'review-operations-filters.db'
    initialize_database(path)
    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
    site, scope_id, device = _private_device(path, 'Operations site', '10.94.0.0/24')
    critical = create_review(title='Critical active', priority='CRITICAL', site_id=site['id'],
        scope_id=scope_id, device_id=device['id'], db_path=path)
    high = create_review(title='High active', priority='HIGH', disposition='BENIGN', db_path=path)
    low = create_review(title='Low closed', priority='LOW', db_path=path)
    ages = {critical['id']: 3, high['id']: 2, low['id']: 1}
    with get_connection(path) as connection:
        for review_id, age in ages.items():
            created = (now-timedelta(days=age)).isoformat()
            updated = (now-timedelta(hours=age)).isoformat()
            connection.execute('UPDATE incident_reviews SET created_at=?,updated_at=? WHERE id=?',
                               (created, updated, review_id))
        connection.execute("UPDATE incident_reviews SET state='CLOSED',closed_at=?,final_summary=? WHERE id=?",
                           (now.isoformat(),'Reviewed and closed.',low['id']))
        connection.execute('''INSERT INTO incident_review_evidence
            (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,?,?,?,?)''',
            (critical['id'],'THREAT_DETECTION',1,now.isoformat(),now.isoformat()))
    kwargs = {'db_path': path, 'now': now}
    assert build_incident_review_operations(**kwargs, state='OPEN')['pagination']['total'] == 2
    assert build_incident_review_operations(**kwargs, priority='CRITICAL')['queue'][0]['id'] == critical['id']
    assert build_incident_review_operations(**kwargs, disposition='BENIGN')['queue'][0]['id'] == high['id']
    assert build_incident_review_operations(**kwargs, site_id=site['id'])['pagination']['total'] == 1
    assert build_incident_review_operations(**kwargs, scope_id=scope_id)['pagination']['total'] == 1
    assert build_incident_review_operations(**kwargs, device_id=device['id'])['pagination']['total'] == 1
    assert build_incident_review_operations(**kwargs, has_evidence=True)['pagination']['total'] == 1
    assert build_incident_review_operations(**kwargs, has_evidence=False)['pagination']['total'] == 2
    assert build_incident_review_operations(**kwargs, state='CLOSED')['queue'][0]['has_final_summary'] is True
    assert [r['priority'] for r in build_incident_review_operations(**kwargs, sort='priority')['queue']] == ['CRITICAL','HIGH','LOW']
    assert [r['id'] for r in build_incident_review_operations(**kwargs, sort='oldest')['queue']] == [critical['id'],high['id'],low['id']]
    assert [r['id'] for r in build_incident_review_operations(**kwargs, sort='newest')['queue']] == [low['id'],high['id'],critical['id']]
    assert [r['id'] for r in build_incident_review_operations(**kwargs, sort='recently_updated')['queue']] == [low['id'],high['id'],critical['id']]
    assert [r['id'] for r in build_incident_review_operations(**kwargs, sort='oldest_open')['queue']] == [critical['id'],high['id'],low['id']]
    page = build_incident_review_operations(**kwargs, sort='oldest', limit=1, offset=1)
    assert page['pagination'] == {'total': 3, 'limit': 1, 'offset': 1}
    assert page['queue'][0]['id'] == high['id']
    for params in ({'limit': 0}, {'limit': 101}, {'offset': -1}, {'offset': 100001}):
        with pytest.raises(IncidentReviewError):
            build_incident_review_operations(**kwargs, **params)


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


def test_migrations_41_to_43_are_additive_idempotent_and_fk_clean(tmp_path,monkeypatch):
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
        columns = {row[1] for row in connection.execute('PRAGMA table_info(incident_reviews)')}
        assert 'final_summary' in columns
        assert max(version for version,_ in MIGRATIONS) == 43


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
        assert connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 43
        after = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {'incident_review_events','incident_review_notes'} <= after - before
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert list_timeline(legacy_review_id,db_path=path)['total'] == 0


def test_migration_43_preserves_timeline_rows_constraints_and_triggers(tmp_path,monkeypatch):
    path = tmp_path / 'review-migration-43.db'
    from database import migrations as migration_module
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS[:42])
    initialize_database(path)
    with get_connection(path) as connection:
        cursor = connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,created_at,updated_at,
            closed_at,disposition) VALUES ('IR-legacy-closed','Legacy closed','','CLOSED',
            'MEDIUM','MEDIUM','2026-01-01','2026-01-01','2026-01-02','INCONCLUSIVE')''')
        review_id = cursor.lastrowid
        note_cursor = connection.execute('''INSERT INTO incident_review_notes (
            incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)''',
            (review_id,'Existing note','OPERATOR','2026-01-01T12:00:00+00:00'))
        event_values = (review_id,'ANALYST_NOTE_ADDED','OPERATOR','2026-01-01T12:00:00+00:00',
            'analyst_note','old','new','THREAT_DETECTION',77,note_cursor.lastrowid,'Existing history row')
        event_cursor = connection.execute('''INSERT INTO incident_review_events (
            incident_review_id,event_type,actor_source,created_at,field_name,old_value,
            new_value,evidence_type,evidence_id,note_id,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            event_values)
        event_id = event_cursor.lastrowid
        event_cursor = connection.execute('SELECT * FROM incident_review_events WHERE id=?',
                                          (event_id,))
        old_row = tuple(event_cursor.fetchone())
    monkeypatch.setattr(migration_module,'MIGRATIONS',MIGRATIONS)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        migrated = tuple(connection.execute('SELECT * FROM incident_review_events WHERE id=?',
                                            (event_id,)).fetchone())
        review_cursor = connection.execute('SELECT state,final_summary FROM incident_reviews WHERE id=?',
                                           (review_id,))
        review = review_cursor.fetchone()
        assert migrated == old_row
        assert review == ('CLOSED',None)
        assert connection.execute('SELECT COUNT(*) FROM schema_migrations WHERE version=43').fetchone()[0] == 1
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_incident_review_events_timeline'").fetchone()
        index_fields = [row[2] for row in connection.execute('PRAGMA index_info(idx_incident_review_events_timeline)')]
        assert index_fields == ['incident_review_id','created_at','id']
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name='incident_review_events_no_update'").fetchone()
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name='incident_review_events_no_delete'").fetchone()
        with pytest.raises(Exception,match='append-only'):
            connection.execute('UPDATE incident_review_events SET summary=? WHERE id=?',('edit',event_id))
        with pytest.raises(Exception,match='append-only'):
            connection.execute('DELETE FROM incident_review_events WHERE id=?',(event_id,))
        next_event = connection.execute('''INSERT INTO incident_review_events (
            incident_review_id,event_type,actor_source,created_at,old_value,new_value,summary)
            VALUES (?,?,?,?,?,?,?)''',(review_id,'FINAL_SUMMARY_CHANGED','OPERATOR',
                '2026-01-03T00:00:00+00:00',None,'Reviewed','Final analyst summary changed'))
        assert next_event.lastrowid > event_id
    assert get_review(review_id,path)['final_summary'] is None


def test_review_timeline_and_notes_are_atomic_bounded_and_ordered(tmp_path):
    path = tmp_path / 'review-history.db'
    review = create_review(title='History review',db_path=path)
    assert [row['event_type'] for row in list_timeline(review['id'],db_path=path)['items']] == ['REVIEW_CREATED']
    update_review(review['id'],{'state':'IN_REVIEW','priority':'HIGH','confidence':'HIGH',
        'disposition':'NEEDS_MONITORING','title':'Updated history review','summary':'Changed'},path)
    update_review(review['id'],{'state':'CLOSED','final_summary':'Review completed.'},path)
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
    closed = update_review(review['id'],{'state':'CLOSED','disposition':'INCONCLUSIVE',
        'final_summary':'Review completed.'},path)
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


def test_13d_close_requires_resolved_disposition_and_final_summary_atomically(tmp_path):
    path = tmp_path / 'review-close-rules.db'
    review = create_review(title='Closure rules',db_path=path)
    initial_events = list_timeline(review['id'],db_path=path)['total']
    with pytest.raises(IncidentReviewError,match='cannot be created'):
        create_review(title='Invalid closed creation',state='CLOSED',
            disposition='BENIGN',final_summary='Already done',db_path=path)
    for patch, message in (({'state':'CLOSED'},'disposition'),
        ({'state':'CLOSED','disposition':'BENIGN'},'summary'),
        ({'state':'CLOSED','disposition':'BENIGN','final_summary':'   '},'summary')):
        with pytest.raises(IncidentReviewError,match=message):
            update_review(review['id'],patch,path)
        unchanged = get_review(review['id'],path)
        assert unchanged['state'] == 'OPEN' and unchanged['disposition'] == 'UNREVIEWED'
        assert unchanged['final_summary'] is None and unchanged['closed_at'] is None
        assert list_timeline(review['id'],db_path=path)['total'] == initial_events

    with get_connection(path) as connection:
        connection.execute('''CREATE TRIGGER fail_final_summary_event BEFORE INSERT ON incident_review_events
            WHEN NEW.event_type='FINAL_SUMMARY_CHANGED'
            BEGIN SELECT RAISE(ABORT,'injected timeline failure'); END''')
    with pytest.raises(Exception,match='injected timeline failure'):
        update_review(review['id'],{'state':'CLOSED','disposition':'BENIGN',
            'final_summary':'Review completed.'},path)
    unchanged = get_review(review['id'],path)
    assert unchanged['state'] == 'OPEN' and unchanged['disposition'] == 'UNREVIEWED'
    assert unchanged['final_summary'] is None and unchanged['closed_at'] is None
    assert list_timeline(review['id'],db_path=path)['total'] == initial_events
    with get_connection(path) as connection:
        connection.execute('DROP TRIGGER fail_final_summary_event')

    closed = update_review(review['id'],{'state':'CLOSED','disposition':'BENIGN',
        'final_summary':'  Review completed from available records.  '},path)
    assert closed['state'] == 'CLOSED' and closed['closed_at']
    assert closed['disposition'] == 'BENIGN'
    assert closed['final_summary'] == 'Review completed from available records.'
    events = list_timeline(review['id'],db_path=path)['items']
    types = [event['event_type'] for event in events]
    assert types.count('REVIEW_CLOSED') == 1
    assert types.count('STATE_CHANGED') == 0
    assert types.count('DISPOSITION_CHANGED') == 1
    assert types.count('FINAL_SUMMARY_CHANGED') == 1
    assert types[:3] == ['FINAL_SUMMARY_CHANGED','DISPOSITION_CHANGED','REVIEW_CLOSED']
    summary_event = next(event for event in events if event['event_type']=='FINAL_SUMMARY_CHANGED')
    assert summary_event['old_value'] is None
    assert summary_event['new_value'] == closed['final_summary']

    event_count = len(events)
    update_review(review['id'],{'state':'CLOSED'},path)
    assert list_timeline(review['id'],db_path=path)['total'] == event_count
    for patch in ({'disposition':'INCONCLUSIVE'},{'final_summary':'Edited while closed'},
                  {'priority':'HIGH'}):
        with pytest.raises(IncidentReviewError,match='Reopen'):
            update_review(review['id'],patch,path)
    assert get_review(review['id'],path)['final_summary'] == closed['final_summary']
    assert list_timeline(review['id'],db_path=path)['total'] == event_count


def test_13d_reopen_and_reclose_preserve_append_only_resolution_history(tmp_path):
    path = tmp_path / 'review-reopen-reclose.db'
    review = create_review(title='Reopen rules',db_path=path)
    first_summary = 'First review outcome.'
    update_review(review['id'],{'final_summary':f' {first_summary} '},path)
    event_count = list_timeline(review['id'],db_path=path)['total']
    update_review(review['id'],{'final_summary':first_summary},path)
    assert list_timeline(review['id'],db_path=path)['total'] == event_count
    update_review(review['id'],{'final_summary':None},path)
    cleared = [event for event in list_timeline(review['id'],db_path=path)['items']
               if event['event_type']=='FINAL_SUMMARY_CHANGED'][0]
    assert cleared['old_value'] == first_summary and cleared['new_value'] is None

    first_closed = update_review(review['id'],{'state':'CLOSED','disposition':'NEEDS_MONITORING',
        'final_summary':first_summary},path)
    history_after_first_close = list_timeline(review['id'],db_path=path)['items']
    reopened = update_review(review['id'],{'state':'IN_REVIEW'},path)
    assert reopened['state'] == 'IN_REVIEW' and reopened['closed_at'] is None
    assert reopened['disposition'] == 'NEEDS_MONITORING'
    assert reopened['final_summary'] == first_summary
    newest = list_timeline(review['id'],db_path=path)['items']
    assert newest[0]['event_type'] == 'REVIEW_REOPENED'
    assert sum(event['event_type']=='STATE_CHANGED' for event in newest) == 0
    assert len(newest) == len(history_after_first_close) + 1

    second_summary = 'Updated after reopening.'
    update_review(review['id'],{'final_summary':second_summary},path)
    second_closed = update_review(review['id'],{'state':'CLOSED'},path)
    assert second_closed['closed_at']
    assert datetime.fromisoformat(second_closed['closed_at']) > datetime.fromisoformat(first_closed['closed_at'])
    final_events = list_timeline(review['id'],db_path=path)['items']
    assert sum(event['event_type']=='REVIEW_CLOSED' for event in final_events) == 2
    assert sum(event['event_type']=='REVIEW_REOPENED' for event in final_events) == 1
    assert sum(event['event_type']=='FINAL_SUMMARY_CHANGED' for event in final_events) == 4
    assert sum(event['event_type']=='STATE_CHANGED' for event in final_events) == 0
    assert first_closed['final_summary'] == first_summary


def test_13d_final_summary_normalization_limits_and_api_create_state(tmp_path):
    from pydantic import ValidationError
    from api.incident_reviews import ReviewCreate
    path = tmp_path / 'review-final-summary-validation.db'
    with pytest.raises(IncidentReviewError,match='Final analyst summary'):
        create_review(title='Too much final summary',final_summary='x' * 4001,db_path=path)
    with pytest.raises(ValidationError):
        ReviewCreate(title='Direct closed',state='CLOSED')
    review = create_review(title='Summary normalization',db_path=path)
    updated = update_review(review['id'],{'final_summary':'  Analyst summary  '},path)
    assert updated['final_summary'] == 'Analyst summary'
    assert update_review(review['id'],{'final_summary':'Analyst summary'},path)['final_summary'] == 'Analyst summary'


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
        ReviewUpdate(state='CLOSED',disposition='NEEDS_MONITORING',
            final_summary='Continue monitoring.',analyst_note='Check next week'))
    assert changed['closed_at'] and changed['final_summary'] == 'Continue monitoring.'
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
