from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI

from api.incident_reviews import register_incident_review_routes
from database.db import get_connection, initialize_database
from database.incident_reviews import IncidentReviewError
from services.incident_review_operations import (
    AGE_BUCKETS,
    build_incident_review_operations,
    build_incident_review_trends,
)

NOW = datetime(2031, 4, 10, 12, 34, 56, 123456, tzinfo=timezone.utc)


def _review(path, *, key, created, state='OPEN', priority='LOW'):
    closed = NOW.isoformat(timespec='microseconds') if state == 'CLOSED' else None
    with get_connection(path) as connection:
        return connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,created_at,updated_at,closed_at,disposition
        ) VALUES (?,?,? ,?,?, 'MEDIUM',?,?,?,'UNREVIEWED')''',
            (key, key, '', state, priority, created.isoformat(timespec='microseconds'),
             created.isoformat(timespec='microseconds'), closed)).lastrowid


def _event(path, review_id, event_type, created):
    with get_connection(path) as connection:
        return connection.execute('''INSERT INTO incident_review_events
            (incident_review_id,event_type,actor_source,created_at,summary)
            VALUES (?,?, 'OPERATOR', ?, 'stored text must not surface')''',
            (review_id, event_type, created.isoformat(timespec='microseconds'))).lastrowid


@pytest.mark.parametrize(('window','bucket','count'), [
    ('24h','1h',24), ('7d','1d',7), ('30d','1d',30), ('90d','1d',90),
])
def test_trends_windows_have_exact_contiguous_zero_filled_buckets(tmp_path, window, bucket, count):
    path = tmp_path / f'trends-{window}.db'
    initialize_database(path)
    result = build_incident_review_trends(db_path=path, window=window, now=NOW)
    assert result['window'] == window and result['bucket'] == bucket
    assert result['window_end'] == NOW.isoformat(timespec='microseconds')
    assert result['series'][0]['bucket_start'] == result['window_start']
    assert result['series'][-1]['bucket_end'] == result['window_end']
    assert len(result['series']) == count
    assert all(set(row) == {'bucket_start','bucket_end','reviews_created',
                            'review_close_events','review_reopen_events'} for row in result['series'])
    assert all(row['reviews_created'] == row['review_close_events'] == row['review_reopen_events'] == 0
               for row in result['series'])
    for previous, current in zip(result['series'], result['series'][1:]):
        assert previous['bucket_end'] == current['bucket_start']


def test_trends_default_invalid_window_and_timezone_validation(tmp_path):
    path = tmp_path / 'trends-window-validation.db'
    initialize_database(path)
    assert build_incident_review_trends(db_path=path, now=NOW)['window'] == '30d'
    for kwargs in ({'window': 'all'}, {'window': '1d'}, {'window': []}):
        with pytest.raises(IncidentReviewError):
            build_incident_review_trends(db_path=path, now=NOW, **kwargs)
    with pytest.raises(IncidentReviewError):
        build_incident_review_trends(db_path=path, now=datetime(2031, 4, 10, 12))


def test_trends_half_open_boundaries_creation_source_and_recorded_lifecycle_events(tmp_path):
    path = tmp_path / 'trends-boundaries.db'
    initialize_database(path)
    empty = build_incident_review_trends(db_path=path, window='24h', now=NOW)
    start, end = datetime.fromisoformat(empty['window_start']), datetime.fromisoformat(empty['window_end'])
    hour = timedelta(hours=1)
    at_start = _review(path, key='IR-START', created=start)
    at_next_start = _review(path, key='IR-NEXT', created=start + hour)
    at_last_start = _review(path, key='IR-LAST', created=end - hour)
    at_end = _review(path, key='IR-END', created=end)
    future = _review(path, key='IR-FUTURE', created=end + timedelta(microseconds=1))
    # The event must not double-count the authoritative incident_reviews.created_at metric.
    _event(path, at_start, 'REVIEW_CREATED', start)
    _event(path, at_start, 'REVIEW_CLOSED', start)
    _event(path, at_start, 'REVIEW_CLOSED', start + hour)
    _event(path, at_start, 'REVIEW_REOPENED', start + hour)
    _event(path, at_start, 'REVIEW_CLOSED', end - timedelta(microseconds=1))
    _event(path, at_start, 'REVIEW_REOPENED', start + 2*hour)
    _event(path, at_start, 'REVIEW_REOPENED', end)
    _event(path, at_start, 'REVIEW_CLOSED', end + timedelta(microseconds=1))

    result = build_incident_review_trends(db_path=path, window='24h', now=NOW)
    assert result['series'][0]['reviews_created'] == 1
    assert result['series'][1]['reviews_created'] == 1
    assert result['series'][-1]['reviews_created'] == 1
    assert sum(row['reviews_created'] for row in result['series']) == 3
    assert result['series'][0]['review_close_events'] == 1
    assert result['series'][1]['review_close_events'] == 1
    assert result['series'][1]['review_reopen_events'] == 1
    assert result['series'][2]['review_reopen_events'] == 1
    assert result['series'][-1]['review_close_events'] == 1
    assert sum(row['review_close_events'] for row in result['series']) == 3
    assert sum(row['review_reopen_events'] for row in result['series']) == 2
    assert at_next_start and at_last_start and at_end and future


def test_trends_snapshot_reuses_current_attention_and_exact_aging_buckets(tmp_path):
    path = tmp_path / 'trends-snapshot.db'
    initialize_database(path)
    review_rows = [
        _review(path, key='IR-LT-1H', created=NOW-timedelta(minutes=30), priority='HIGH'),
        _review(path, key='IR-H1-24', created=NOW-timedelta(hours=2), state='IN_REVIEW'),
        _review(path, key='IR-D1-3', created=NOW-timedelta(days=2)),
        _review(path, key='IR-D3-7', created=NOW-timedelta(days=5), state='IN_REVIEW'),
        _review(path, key='IR-GT-7D', created=NOW-timedelta(days=9)),
        _review(path, key='IR-CLOSED', created=NOW-timedelta(days=10), state='CLOSED', priority='CRITICAL'),
    ]
    result = build_incident_review_trends(db_path=path, now=NOW)
    snapshot = result['current_snapshot']
    operations = build_incident_review_operations(db_path=path, now=NOW, limit=1)
    assert snapshot == {
        'as_of': NOW.isoformat(timespec='microseconds'),
        'open_count': 3,
        'in_review_count': 2,
        'closed_count': 1,
        'unresolved_count': 5,
        'reviews_needing_attention': operations['summary']['reviews_needing_attention'],
        'age_buckets': {'LT_1H': 1, 'H1_24': 1, 'D1_3': 1, 'D3_7': 1, 'GT_7D': 1},
        'oldest_active_age_seconds': 9*86400,
    }
    assert snapshot['reviews_needing_attention'] == 5
    assert set(result) == {'window','bucket','window_start','window_end','series','current_snapshot'}
    assert not {'unresolved_by_bucket','open_by_bucket','attention_by_bucket'} & set(result)
    assert set(snapshot['age_buckets']) == set(AGE_BUCKETS)
    assert review_rows


def test_trends_closed_only_and_empty_active_workload_has_null_oldest_age(tmp_path):
    path = tmp_path / 'trends-closed-only.db'
    initialize_database(path)
    _review(path, key='IR-CLOSED', created=NOW-timedelta(days=2), state='CLOSED')
    snapshot = build_incident_review_trends(db_path=path, now=NOW)['current_snapshot']
    assert snapshot['closed_count'] == 1
    assert snapshot['unresolved_count'] == 0
    assert snapshot['age_buckets'] == {key: 0 for key in AGE_BUCKETS}
    assert snapshot['oldest_active_age_seconds'] is None


def test_trends_get_is_read_only_and_query_plans_are_bounded_sources(tmp_path):
    path = tmp_path / 'trends-read-only.db'
    initialize_database(path)
    _review(path, key='IR-PLAN', created=NOW-timedelta(days=1))
    with get_connection(path) as connection:
        tables = ('incident_reviews','incident_review_events','incident_review_notes',
                  'incident_review_evidence','sites','authorized_scopes','devices',
                  'perimeter_detections','perimeter_policy_correlations','perimeter_host_correlations',
                  'external_exposure_changes','threat_detections','correlations','web_detections')
        before = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                  for table in tables}
    result = build_incident_review_trends(db_path=path, now=NOW, explain=True)
    assert set(result['query_plans']) == {'reviews_created','review_events','current_snapshot'}
    plans = result['query_plans']
    assert any('incident_reviews' in row['detail'] for row in plans['reviews_created'])
    assert any('incident_review_events' in row['detail'] for row in plans['review_events'])
    assert plans['current_snapshot']
    with get_connection(path) as connection:
        after = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                 for table in tables}
    assert before == after


def test_trends_endpoint_defaults_and_rejects_unapproved_window(tmp_path):
    path = tmp_path / 'trends-api.db'
    initialize_database(path)
    app = FastAPI()
    register_incident_review_routes(app, lambda: path)
    endpoint = next(route.endpoint for route in app.routes
                    if getattr(route, 'path', None) == '/incident-review-operations/trends')
    assert endpoint()['window'] == '30d'
    with pytest.raises(Exception) as invalid:
        endpoint(window='14d')
    assert getattr(invalid.value, 'status_code', None) == 422
    parameter = app.openapi()['paths']['/incident-review-operations/trends']['get']['parameters'][0]
    assert parameter['schema']['enum'] == ['24h', '7d', '30d', '90d']
