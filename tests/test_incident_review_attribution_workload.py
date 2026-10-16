from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

import api.main as api
from database.db import get_connection, initialize_database
from database.incident_reviews import IncidentReviewError
from database.inventory import create_device
from database.networks import create_network
from services.incident_review_operations import (
    build_incident_review_device_workload,
    build_incident_review_operations,
    build_incident_review_scope_workload,
)

NOW = datetime(2030, 4, 10, 12, tzinfo=timezone.utc)


def _seed(path):
    initialize_database(path)
    with get_connection(path) as connection:
        site_a = connection.execute(
            "INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('North',1,?,?)",
            (NOW.isoformat(), NOW.isoformat())).lastrowid
        site_b = connection.execute(
            "INSERT INTO sites (name,enabled,created_at,updated_at) VALUES ('South',1,?,?)",
            (NOW.isoformat(), NOW.isoformat())).lastrowid

    def inventory(prefix, site_id, cidr, scope_name, device_key, hostname):
        network = create_network(cidr, prefix, 'fixture', True, True, path)
        with get_connection(path) as connection:
            scope_id = connection.execute(
                'SELECT scope_id FROM network_scope_links WHERE network_id=?',
                (network['id'],)).fetchone()[0]
            connection.execute(
                'UPDATE authorized_scopes SET name=? WHERE id=?', (scope_name, scope_id))
            connection.execute(
                'INSERT INTO remote_scope_sites (scope_id,site_id,created_at) VALUES (?,?,?)',
                (scope_id, site_id, NOW.isoformat()))
        device = create_device(
            stable_key=device_key, network_id=network['id'], mac_address=None,
            hostname=hostname, vendor=None, first_seen=NOW.isoformat(),
            last_seen=NOW.isoformat(), last_ip_address=cidr.split('/')[0],
            status='ONLINE', identity_confidence='LOW', db_path=path)
        return scope_id, device['id']

    scope_a, device_a = inventory('north-a', site_a, '10.41.0.0/24', 'Alpha scope',
                                  'device-host', 'edge-host')
    scope_b, device_b = inventory('north-b', site_a, '10.42.0.0/24', '',
                                  'device-stable-key', '   ')
    scope_c, device_c = inventory('north-c', site_a, '10.43.0.0/24', 'Gamma scope',
                                  '', None)
    scope_s, device_s = inventory('south', site_b, '10.44.0.0/24', 'South scope',
                                  'south-device', 'south-host')

    def review(key, *, site_id, scope_id, device_id, state='OPEN', priority='LOW',
               created=None, updated=None, closed=None):
        created = created or NOW
        updated = updated or created
        with get_connection(path) as connection:
            return connection.execute("""INSERT INTO incident_reviews (
                incident_key,title,summary,state,priority,confidence,site_id,scope_id,device_id,
                created_at,updated_at,closed_at,disposition
            ) VALUES (?,?, '', ?,?,'MEDIUM',?,?,?,?,?,?, 'UNREVIEWED')""",
                (key, key, state, priority, site_id, scope_id, device_id,
                 created.isoformat(), updated.isoformat(),
                 closed.isoformat() if closed else None)).lastrowid

    review_a = review('IR-14D-NORTH-A', site_id=site_a, scope_id=scope_a, device_id=device_a,
                      priority='HIGH', created=NOW-timedelta(days=4), updated=NOW-timedelta(days=4))
    review_b = review('IR-14D-NORTH-B', site_id=site_a, scope_id=scope_a, device_id=None,
                      state='IN_REVIEW', created=NOW-timedelta(hours=2), updated=NOW-timedelta(days=1))
    review_c = review('IR-14D-NORTH-C', site_id=site_a, scope_id=scope_b, device_id=device_b,
                      state='CLOSED', created=NOW-timedelta(days=10), updated=NOW-timedelta(minutes=10),
                      closed=NOW-timedelta(hours=1))
    review_d = review('IR-14D-NORTH-UNATTR-SCOPE', site_id=site_a, scope_id=None,
                      device_id=device_c, created=NOW-timedelta(days=2), updated=NOW-timedelta(days=2))
    review_e = review('IR-14D-UNATTR-SITE-ATTR', site_id=None, scope_id=scope_a,
                      device_id=device_a, created=NOW-timedelta(days=1), updated=NOW-timedelta(days=1))
    review_f = review('IR-14D-UNATTR-SITE-NULL', site_id=None, scope_id=None,
                      device_id=None, created=NOW-timedelta(days=3), updated=NOW-timedelta(minutes=20))
    review_g = review('IR-14D-SOUTH', site_id=site_b, scope_id=scope_s, device_id=device_s,
                      priority='CRITICAL', created=NOW-timedelta(days=8), updated=NOW-timedelta(days=8))

    with get_connection(path) as connection:
        connection.execute("INSERT INTO incident_review_events (incident_review_id,event_type,actor_source,created_at,summary) VALUES (?,?,?,?,?)",
                           (review_a, 'REVIEW_CREATED', 'OPERATOR', (NOW-timedelta(hours=1)).isoformat(), 'Event activity'))
        connection.execute("INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)",
                           (review_b, 'Recent note', 'OPERATOR', (NOW-timedelta(minutes=5)).isoformat()))
        connection.execute("INSERT INTO incident_review_events (incident_review_id,event_type,actor_source,created_at,summary) VALUES (?,?,?,?,?)",
                           (review_d, 'REVIEW_CREATED', 'OPERATOR', (NOW-timedelta(minutes=3)).isoformat(), 'Unattributed scope event'))

    return {
        'site_a': site_a, 'site_b': site_b,
        'scope_a': scope_a, 'scope_b': scope_b, 'scope_c': scope_c, 'scope_s': scope_s,
        'device_a': device_a, 'device_b': device_b, 'device_c': device_c, 'device_s': device_s,
        'reviews': (review_a, review_b, review_c, review_d, review_e, review_f, review_g),
    }


def test_scoped_scope_and_device_workloads_and_attention_reuse(tmp_path):
    path = tmp_path / 'attribution-workloads.db'
    ids = _seed(path)
    scopes = build_incident_review_scope_workload(site_id=ids['site_a'], db_path=path, now=NOW)
    assert scopes['pagination'] == {'limit': 20, 'offset': 0, 'total': 3}
    scope_rows = {row['scope_id']: row for row in scopes['scopes']}
    alpha = scope_rows[ids['scope_a']]
    assert set(alpha) == {'scope_id','scope_name','scope_type','canonical_target','total_reviews',
        'unresolved_reviews','open_reviews','in_review_reviews','closed_reviews',
        'reviews_needing_attention','high_priority_unresolved','oldest_active_created_at',
        'oldest_active_age_seconds','latest_review_activity_at'}
    assert alpha['scope_name'] == 'Alpha scope' and alpha['scope_type'] == 'PRIVATE_NETWORK'
    assert alpha['canonical_target'] == '10.41.0.0/24'
    assert (alpha['total_reviews'], alpha['unresolved_reviews'], alpha['open_reviews'],
            alpha['in_review_reviews'], alpha['closed_reviews']) == (2, 2, 1, 1, 0)
    assert alpha['reviews_needing_attention'] == 2
    assert build_incident_review_operations(db_path=path, now=NOW, site_id=ids['site_a'],
        scope_id=ids['scope_a'], has_attention=True)['pagination']['total'] == alpha['reviews_needing_attention']
    assert alpha['high_priority_unresolved'] == 1
    assert alpha['oldest_active_created_at'] == (NOW-timedelta(days=4)).isoformat()
    assert alpha['oldest_active_age_seconds'] == 4*86400
    assert alpha['latest_review_activity_at'] == (NOW-timedelta(minutes=5)).isoformat()
    assert scope_rows[ids['scope_b']]['scope_name'] is None
    assert scope_rows[ids['scope_b']]['canonical_target'] == '10.42.0.0/24'
    assert scope_rows[ids['scope_b']]['oldest_active_created_at'] is None
    assert scope_rows[ids['scope_b']]['latest_review_activity_at'] == (NOW-timedelta(minutes=10)).isoformat()
    assert scope_rows[None]['scope_name'] == 'Unattributed'
    assert scope_rows[None]['scope_type'] is None and scope_rows[None]['canonical_target'] is None
    assert scope_rows[None]['latest_review_activity_at'] == (NOW-timedelta(minutes=3)).isoformat()

    devices = build_incident_review_device_workload(site_id=ids['site_a'], db_path=path, now=NOW)
    assert devices['pagination']['total'] == 4
    device_rows = {row['device_id']: row for row in devices['devices']}
    assert set(device_rows[ids['device_a']]) == {'device_id','device_label','hostname','total_reviews',
        'unresolved_reviews','reviews_needing_attention','high_priority_unresolved',
        'oldest_active_created_at','oldest_active_age_seconds','latest_review_activity_at'}
    assert device_rows[ids['device_a']]['device_label'] == 'edge-host'
    assert device_rows[ids['device_a']]['hostname'] == 'edge-host'
    assert device_rows[ids['device_b']]['device_label'] == 'device-stable-key'
    assert device_rows[ids['device_c']]['device_label'] == f"Device #{ids['device_c']}"
    assert device_rows[None]['device_label'] == 'Unattributed'
    assert device_rows[None]['hostname'] is None


def test_unattributed_site_context_keeps_explicit_scope_and_device_attribution(tmp_path):
    path = tmp_path / 'unattributed-context.db'
    ids = _seed(path)
    scopes = build_incident_review_scope_workload(unattributed_only=True, db_path=path, now=NOW)
    devices = build_incident_review_device_workload(unattributed_only=True, db_path=path, now=NOW)
    assert scopes['pagination']['total'] == 2
    assert [row['scope_id'] for row in scopes['scopes']] == [ids['scope_a'], None]
    assert devices['pagination']['total'] == 2
    assert [row['device_id'] for row in devices['devices']] == [ids['device_a'], None]
    assert all(ids['site_a'] != row.get('site_id') for row in scopes['scopes'])


def test_scoped_workload_sorts_pagination_context_validation_and_plan(tmp_path):
    path = tmp_path / 'workload-sort-plan.db'
    ids = _seed(path)
    kwargs = {'site_id': ids['site_a'], 'db_path': path, 'now': NOW}
    assert [r['scope_id'] for r in build_incident_review_scope_workload(**kwargs, sort='unresolved_desc')['scopes']] == [ids['scope_a'], None, ids['scope_b']]
    assert [r['scope_id'] for r in build_incident_review_scope_workload(**kwargs, sort='attention_desc')['scopes']] == [ids['scope_a'], None, ids['scope_b']]
    assert [r['scope_id'] for r in build_incident_review_scope_workload(**kwargs, sort='oldest_active')['scopes']] == [ids['scope_a'], None, ids['scope_b']]
    assert [r['scope_id'] for r in build_incident_review_scope_workload(**kwargs, sort='recent_activity')['scopes']] == [None, ids['scope_a'], ids['scope_b']]
    assert [r['scope_id'] for r in build_incident_review_scope_workload(**kwargs, sort='name')['scopes']] == [ids['scope_a'], None, ids['scope_b']]
    assert [r['device_id'] for r in build_incident_review_device_workload(**kwargs, sort='unresolved_desc')['devices']] == [ids['device_a'], ids['device_c'], None, ids['device_b']]
    assert [r['device_id'] for r in build_incident_review_device_workload(**kwargs, sort='attention_desc')['devices']] == [ids['device_a'], ids['device_c'], None, ids['device_b']]
    assert [r['device_id'] for r in build_incident_review_device_workload(**kwargs, sort='oldest_active')['devices']] == [ids['device_a'], ids['device_c'], None, ids['device_b']]
    assert [r['device_id'] for r in build_incident_review_device_workload(**kwargs, sort='label')['devices']] == [ids['device_c'], ids['device_b'], ids['device_a'], None]
    assert [r['device_id'] for r in build_incident_review_device_workload(**kwargs, sort='recent_activity')['devices']] == [ids['device_c'], None, ids['device_b'], ids['device_a']]
    assert build_incident_review_scope_workload(**kwargs, limit=1, offset=1)['pagination']['total'] == 3
    assert len(build_incident_review_device_workload(**kwargs, limit=1, offset=1)['devices']) == 1
    assert build_incident_review_scope_workload(**kwargs, limit=100, offset=100000)['pagination']['total'] == 3
    for options in (
        {}, {'unattributed_only': False}, {'site_id': ids['site_a'], 'unattributed_only': True},
        {'site_id': 0}, {'site_id': 999999}, {'site_id': ids['site_a'], 'sort': 'created_at'},
        {'site_id': ids['site_a'], 'limit': 0}, {'site_id': ids['site_a'], 'limit': 101},
        {'site_id': ids['site_a'], 'offset': -1}, {'site_id': ids['site_a'], 'offset': 100001},
    ):
        with pytest.raises(IncidentReviewError):
            build_incident_review_scope_workload(db_path=path, now=NOW, **options)
    for options in ({'unattributed_only': True, 'sort': 'created_at'}, {'unattributed_only': True, 'limit': 0}):
        with pytest.raises(IncidentReviewError):
            build_incident_review_device_workload(db_path=path, now=NOW, **options)

    for builder, join_detail in (
        (build_incident_review_scope_workload, 'SEARCH s USING INTEGER PRIMARY KEY'),
        (build_incident_review_device_workload, 'SEARCH d USING INTEGER PRIMARY KEY'),
    ):
        plan = builder(**kwargs, explain=True)['query_plan']
        details = '\n'.join(row['detail'] for row in plan)
        assert 'idx_incident_reviews_site' in details
        assert join_detail in details
        assert 'idx_incident_review_events_timeline' in details
        assert 'idx_incident_review_notes_timeline' in details
        assert 'TEMP B-TREE' in details


def test_attribution_queue_null_filters_and_conflicts(tmp_path):
    path = tmp_path / 'attribution-queue-filter.db'
    ids = _seed(path)
    null_scope = build_incident_review_operations(db_path=path, site_id=ids['site_a'],
                                                   unattributed_scope_only=True)
    assert null_scope['pagination']['total'] == 1
    assert null_scope['queue'][0]['scope_id'] is None
    null_device = build_incident_review_operations(db_path=path, site_id=ids['site_a'],
                                                    unattributed_device_only=True)
    assert null_device['pagination']['total'] == 1
    assert all(row['device_id'] is None for row in null_device['queue'])
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, scope_id=ids['scope_a'],
                                         unattributed_scope_only=True)
    with pytest.raises(IncidentReviewError):
        build_incident_review_operations(db_path=path, device_id=ids['device_a'],
                                         unattributed_device_only=True)


def test_attribution_workload_apis_validate_context_and_are_read_only(tmp_path, monkeypatch):
    path = tmp_path / 'attribution-api.db'
    ids = _seed(path)
    monkeypatch.setattr(api, 'DB_PATH', path)
    routes = {(route.path, method): route.endpoint for route in api.app.routes
              if hasattr(route, 'endpoint') for method in getattr(route, 'methods', ())}
    scope_endpoint = routes[('/incident-review-operations/scopes', 'GET')]
    device_endpoint = routes[('/incident-review-operations/devices', 'GET')]
    queue_endpoint = routes[('/incident-review-operations', 'GET')]
    for endpoint in (scope_endpoint, device_endpoint):
        with pytest.raises(HTTPException):
            endpoint(site_id=None, unattributed_only=False, sort='unresolved_desc', limit=20, offset=0)
        with pytest.raises(HTTPException):
            endpoint(site_id=ids['site_a'], unattributed_only=True, sort='unresolved_desc', limit=20, offset=0)
        with pytest.raises(HTTPException) as missing:
            endpoint(site_id=999999, unattributed_only=False, sort='unresolved_desc', limit=20, offset=0)
        assert missing.value.status_code == 404
    with pytest.raises(HTTPException):
        queue_endpoint(state=None, priority=None, disposition=None, site_id=None,
            scope_id=ids['scope_a'], device_id=None, has_evidence=None, age_bucket=None,
            unresolved_only=False, has_attention=None, attention_signal=None,
            unattributed_only=False, unattributed_scope_only=True,
            unattributed_device_only=False, sort='newest', limit=20, offset=0)
    tables = ('incident_reviews','incident_review_evidence','incident_review_notes','incident_review_events',
              'sites','authorized_scopes','devices','threat_detections','correlations','web_detections',
              'perimeter_detections','perimeter_policy_correlations','perimeter_host_correlations',
              'external_exposure_changes')
    with get_connection(path) as connection:
        before = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in tables}
    scopes = scope_endpoint(site_id=ids['site_a'], unattributed_only=False, sort='name', limit=100, offset=0)
    devices = device_endpoint(site_id=None, unattributed_only=True, sort='label', limit=100, offset=0)
    assert scopes['pagination']['total'] == 3 and devices['pagination']['total'] == 2
    with get_connection(path) as connection:
        after = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in tables}
    assert after == before

