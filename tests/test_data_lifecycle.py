import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request

from api.data_lifecycle import register_data_lifecycle_routes
from api.data_lifecycle import CleanupRequest
from api.remote_sensors import local_management
from database.data_lifecycle import _parse_retention, cleanup_data_lifecycle, preview_data_lifecycle
from database.db import get_connection, initialize_database
from database.event_exports import get_bounded_export_events
from database.telemetry import create_web_observation, provision_sensor
from database.web_detections import upsert_detections
from services.finding_models import FindingConfidence, FindingSeverity
from services.telemetry_models import WebObservation
from services.web_detection_models import (
    WebDetection, WebDetectionState, WebDetectionType, WebEvidence,
)

NOW = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)


@pytest.fixture
def lifecycle_context(tmp_path):
    path = tmp_path / "lifecycle.db"
    initialize_database(path)
    app = FastAPI()
    register_data_lifecycle_routes(app, lambda: path)
    endpoint = next(route.endpoint for route in app.routes
                    if getattr(route, "path", None) == "/data-lifecycle/preview")
    return {"path": path, "app": app, "endpoint": endpoint}


def call_preview(context, headers=None, *, client=("127.0.0.1", 5050), host="127.0.0.1",
                 query_string=b"", body=b""):
    raw_headers = [(b"host", host.encode())] + [
        (key.lower().encode(), value.encode()) for key, value in (headers or {}).items()
    ]
    if body:
        raw_headers.append((b"content-length", str(len(body)).encode()))
    request = Request({
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": "/data-lifecycle/preview", "raw_path": b"/data-lifecycle/preview",
        "query_string": query_string, "root_path": "",
        "headers": raw_headers,
        "client": client, "server": ("127.0.0.1", 8000),
    })
    response = Response()
    try:
        local_management(request, response)
        result = context["endpoint"](request=request, response=response)
        return SimpleNamespace(status_code=200, headers=response.headers, json=lambda: result)
    except HTTPException as exc:
        return SimpleNamespace(status_code=exc.status_code, headers=response.headers,
                               json=lambda: {"detail": exc.detail})


def insert_dns(path, deadline, key):
    sensor = ensure_sensor(path, "DNS")
    with get_connection(path) as connection:
        return connection.execute(
            """INSERT INTO dns_observations (
                sensor_id, external_event_id, observed_at, received_at, queried_domain,
                query_type, response_status, resolved_addresses_json, source, retention_until
            ) VALUES (?, ?, ?, ?, 'example.test', 'A', 'NOERROR', '[]', 'test', ?)""",
            (sensor, key, NOW.isoformat(), NOW.isoformat(), deadline),
        ).lastrowid


def insert_legacy_event(path, timestamp, *, source_ip="192.0.2.8", username=None,
                        event_type="LOGIN_FAILED", severity="WARNING",
                        message="SSH login failed", event_count=1):
    with get_connection(path) as connection:
        return connection.execute(
            """INSERT INTO events(timestamp,source_ip,username,event_type,severity,message,event_count)
               VALUES(?,?,?,?,?,?,?)""",
            (timestamp, source_ip, username, event_type, severity, message, event_count),
        ).lastrowid


def protect_legacy_event(path, event_id):
    with get_connection(path) as connection:
        cursor = connection.execute(
            """INSERT INTO threat_detections (
                stable_key,threat_type,state,severity,confidence,source_ip,
                primary_evidence_type,primary_evidence_id,anchor_id,reason,recommendation,
                rule_id,rule_version,first_seen,last_seen,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f"ssh-threat-{event_id}", "SSH_BRUTE_FORCE_THREAT", "SUSPECTED", "MEDIUM",
             "MEDIUM", "192.0.2.8", "SSH_EVENT", event_id, event_id, "Repeated SSH failures.",
             "Review authentication activity.", "test-rule", "1", NOW.isoformat(),
             NOW.isoformat(), NOW.isoformat(), NOW.isoformat()),
        )
        threat_id = cursor.lastrowid
        snapshot = json.dumps({
            "evidence_id": event_id, "source_ip": "192.0.2.8", "username": None,
            "event_type": "LOGIN_FAILED", "event_count": 1,
            "timestamp": "2026-07-01T12:00:00",
        }, sort_keys=True, separators=(",", ":"))
        connection.execute(
            """INSERT INTO threat_evidence(
                threat_id,evidence_type,evidence_id,ssh_event_id,evidence_snapshot
            ) VALUES (?,'SSH_EVENT',?,?,?)""",
            (threat_id, event_id, event_id, snapshot),
        )
        return threat_id, snapshot


def ensure_sensor(path, sensor_type):
    with get_connection(path) as connection:
        row = connection.execute(
            "SELECT id FROM telemetry_sensors WHERE sensor_type=? ORDER BY id LIMIT 1",
            (sensor_type,),
        ).fetchone()
    if row:
        return row[0]
    sensor, _ = provision_sensor(
        "lifecycle-" + sensor_type.lower(), "Lifecycle sensor", sensor_type, None,
        "DOMAIN_ONLY", 30, path,
    )
    return sensor["id"]


def insert_web(path, deadline, key, *, make_detection=False, invalid_snapshot=False):
    sensor_id = ensure_sensor(path, "BROWSER")
    if make_detection:
        observation = WebObservation(
            external_event_id=key, sensor_id=str(sensor_id), observed_at=NOW,
            event_type="FORM_SIGNAL", url="https://login.example.test/private",
            privacy_mode="DOMAIN_ONLY", has_password_form=True, browser_session_id="session",
            tab_id="tab", received_at=NOW, retention_until=datetime.fromisoformat(deadline),
        )
        evidence = WebEvidence.from_row(create_web_observation(observation, path))
        detection = WebDetection(
            detection_type=WebDetectionType.LOGIN_DOMAIN_REVIEW,
            severity=FindingSeverity.LOW, confidence=FindingConfidence.MEDIUM,
            state=WebDetectionState.REVIEW, sensor_id=sensor_id, device_id=None,
            primary_observation_id=evidence.observation_id, hostname=evidence.hostname,
            reason="Review login form signal.", evidence=(evidence,), rule_id="test-rule",
            rule_version="1", first_seen=NOW, last_seen=NOW,
        )
        upsert_detections((detection,), path)
        if invalid_snapshot:
            with get_connection(path) as connection:
                connection.execute(
                    "UPDATE web_detections SET structured_evidence=? WHERE primary_observation_id=?",
                    (json.dumps([{"observation_id": evidence.observation_id}]), evidence.observation_id),
                )
        return evidence.observation_id
    with get_connection(path) as connection:
        return connection.execute(
            """INSERT INTO web_observations (
                sensor_id, external_event_id, observed_at, received_at, event_type,
                hostname, has_login_form, has_password_form, download_detected, source,
                retention_until
            ) VALUES (?, ?, ?, ?, 'NAVIGATION', 'example.test', 0, 0, 0, 'browser', ?)""",
            (sensor_id, key, NOW.isoformat(), NOW.isoformat(), deadline),
        ).lastrowid


def get_item(result, name):
    return next(item for item in result["items"] if item["data_class"] == name)


def test_preview_route_is_direct_local_no_store_and_fixed(lifecycle_context):
    context = lifecycle_context
    response = call_preview(context)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert set(payload) == {"evaluated_at", "items"}
    assert len(payload["items"]) >= 25
    item_keys = {
        "data_class", "policy_state", "total_rows", "expired_rows", "eligible_rows",
        "protected_by_review", "protected_by_dependency", "policy_undefined",
        "invalid_retention_rows", "oldest_eligible_at",
    }
    legacy_keys = {
        "malformed_skipped_rows", "future_skipped_rows", "oldest_retained_at",
        "retention_days", "evaluated_at_local", "cutoff_at_local", "max_delete_rows",
    }
    assert all(set(item) == item_keys | (legacy_keys if item["data_class"] == "LEGACY_EVENTS" else set())
               for item in payload["items"])
    assert [item["data_class"] for item in payload["items"]] == [
        "LEGACY_EVENTS", "NETWORKS", "DEVICES", "DEVICE_OBSERVATIONS", "INVENTORY_HISTORY",
        "CVE_CATALOG", "TELEMETRY_SENSORS", "DNS_OBSERVATIONS", "WEB_OBSERVATIONS",
        "WEB_DETECTIONS", "THREAT_DETECTIONS", "THREAT_CORRELATIONS", "LEGACY_INCIDENTS",
        "PERIMETER_EVENTS", "PERIMETER_DETECTIONS", "PERIMETER_POLICY_CORRELATIONS",
        "PERIMETER_HOST_CORRELATIONS", "EXTERNAL_EXPOSURES", "EXTERNAL_EXPOSURE_OBSERVATIONS",
        "EXTERNAL_EXPOSURE_CHANGES", "EXTERNAL_EXPOSURE_ASSESSMENTS", "REMOTE_SENSOR_TASKS",
        "REMOTE_SENSORS", "ENROLLMENT_RECORDS", "SITES", "SCOPES", "SENSOR_ASSIGNMENTS",
        "INCIDENT_REVIEWS", "REVIEW_EVIDENCE_LINKS", "REVIEW_NOTES", "REVIEW_TIMELINE",
        "SENSOR_TRANSPORT_NONCES", "SCHEMA_MIGRATIONS",
    ]
    assert "metadata_json" not in json.dumps(payload)
    assert any(dependency.dependency is local_management for dependency in next(
        route for route in context["app"].routes
        if getattr(route, "path", None) == "/data-lifecycle/preview"
    ).dependencies)


@pytest.mark.parametrize("headers", [
    {"x-forwarded-for": "127.0.0.1"},
    {"authorization": "Bearer secret"},
    {"x-sentinelip-sensor-id": "1"},
    {"x-sentinelip-sensor-token": "secret"},
    {"x-sensor-uuid": "sensor-secret"},
])
def test_preview_reuses_local_management_rejections(lifecycle_context, headers):
    response = call_preview(lifecycle_context, headers=headers)
    assert response.status_code == 403
    # Match the shared guard contract: rejected dependency responses need not set no-store.


def test_preview_rejects_nonlocal_and_nonlocal_host(lifecycle_context):
    assert call_preview(lifecycle_context, client=("192.0.2.1", 5050)).status_code == 403
    assert call_preview(lifecycle_context, host="example.test").status_code == 403
    assert call_preview(lifecycle_context, headers={"origin": "https://example.test"}).status_code == 403


def test_preview_rejects_query_parameters_and_request_body(lifecycle_context):
    assert call_preview(lifecycle_context, query_string=b"table=events").status_code == 422
    assert call_preview(lifecycle_context, body=b"{}").status_code == 422


def test_dns_deadline_boundary_null_and_malformed_handling(lifecycle_context):
    path = lifecycle_context["path"]
    insert_dns(path, (NOW - timedelta(seconds=1)).isoformat(), "expired")
    insert_dns(path, NOW.isoformat(), "boundary")
    insert_dns(path, (NOW + timedelta(days=1)).isoformat(), "future")
    insert_dns(path, "not-a-time", "malformed")
    with get_connection(path) as connection:
        connection.execute("UPDATE dns_observations SET retention_until='2026-10-17T12:00:00' WHERE external_event_id='boundary'")
    result = preview_data_lifecycle(path, NOW)
    item = get_item(result, "DNS_OBSERVATIONS")
    assert item["total_rows"] == 4
    assert item["expired_rows"] == 2
    assert item["eligible_rows"] == 2
    assert item["invalid_retention_rows"] == 1
    assert item["policy_undefined"] == 0
    assert item["oldest_eligible_at"] == "2026-10-17T11:59:59Z"
    assert _parse_retention(None) == (None, "null")


def test_web_dependency_snapshot_controls_preview_protection(lifecycle_context):
    path = lifecycle_context["path"]
    eligible_id = insert_web(path, (NOW - timedelta(days=1)).isoformat(), "eligible", make_detection=True)
    with get_connection(path) as connection:
        connection.execute(
            """INSERT INTO web_detections (
                stable_key, detection_type, severity, confidence, state, sensor_id, device_id,
                primary_observation_id, hostname, reason, structured_evidence, rule_id,
                rule_version, first_seen, last_seen, created_at, updated_at
            )
            SELECT stable_key || '-second', detection_type, severity, confidence, state, sensor_id,
                device_id, primary_observation_id, hostname, reason, structured_evidence, rule_id,
                rule_version, first_seen, last_seen, created_at, updated_at
            FROM web_detections WHERE primary_observation_id=?""",
            (eligible_id,),
        )
        second_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
        connection.execute(
            "INSERT INTO web_detection_observations(detection_id, observation_id) VALUES (?, ?)",
            (second_id, eligible_id),
        )
    protected_id = insert_web(path, (NOW - timedelta(days=2)).isoformat(), "protected",
                              make_detection=True, invalid_snapshot=True)
    insert_web(path, (NOW + timedelta(days=1)).isoformat(), "future")
    insert_web(path, "invalid-date", "malformed")
    result = preview_data_lifecycle(path, NOW)
    item = get_item(result, "WEB_OBSERVATIONS")
    assert eligible_id != protected_id
    assert item["total_rows"] == 4
    assert item["expired_rows"] == 2
    assert item["eligible_rows"] == 1
    assert item["protected_by_dependency"] == 1
    assert item["protected_by_review"] == 0
    assert item["invalid_retention_rows"] == 1
    assert item["oldest_eligible_at"] == "2026-10-16T12:00:00Z"


def test_preview_policy_classes_and_database_are_unchanged(lifecycle_context):
    path = lifecycle_context["path"]
    with get_connection(path) as connection:
        connection.execute("INSERT INTO events(timestamp,source_ip,event_type,severity,message,event_count) VALUES('x','1.2.3.4','x','INFO','private',1)")
        before = {name: connection.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                  for name in ("events", "remote_sensor_tasks")}
    result = preview_data_lifecycle(path, NOW)
    legacy = get_item(result, "LEGACY_EVENTS")
    assert legacy["policy_state"] == "ACTIVE_RETENTION_POLICY"
    assert legacy["retention_days"] == 90
    assert legacy["malformed_skipped_rows"] == 1
    assert legacy["policy_undefined"] == 0
    assert get_item(result, "REMOTE_SENSOR_TASKS")["policy_undefined"] == 0
    preserved = get_item(result, "DEVICES")
    assert preserved["policy_state"] == "PRESERVE"
    assert preserved["expired_rows"] == preserved["eligible_rows"] == preserved["policy_undefined"] == 0
    transient = get_item(result, "SENSOR_TRANSPORT_NONCES")
    assert transient["policy_state"] == "TRANSIENT_INTERNAL"
    assert transient["eligible_rows"] == transient["policy_undefined"] == 0
    with get_connection(path) as connection:
        after = {name: connection.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                 for name in ("events", "remote_sensor_tasks")}
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
    assert before == after


def test_preview_uses_request_clock_and_does_not_query_payload_fields(lifecycle_context, monkeypatch):
    path = lifecycle_context["path"]
    deadline = (NOW - timedelta(seconds=1)).isoformat()
    insert_dns(path, deadline, "one")
    import database.data_lifecycle as lifecycle
    calls = []
    monkeypatch.setattr(lifecycle, "_utc_now", lambda: calls.append(1) or NOW)
    result = preview_data_lifecycle(path)
    assert result["evaluated_at"] == "2026-10-17T12:00:00Z"
    assert calls == [1]
    assert "queried_domain" not in json.dumps(result)


def test_schema_remains_46_and_preview_is_read_only(lifecycle_context):
    path = lifecycle_context["path"]
    with get_connection(path) as connection:
        before = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        tables_before = connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    preview_data_lifecycle(path, NOW)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == before
        assert connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == tables_before


def test_dns_cleanup_is_bounded_oldest_first_and_counts_only(lifecycle_context):
    path = lifecycle_context["path"]
    for i in range(105):
        insert_dns(path, (NOW - timedelta(days=105-i)).isoformat(), f"expired-{i}")
    insert_dns(path, (NOW + timedelta(days=1)).isoformat(), "future")
    insert_dns(path, "broken-date", "malformed")
    result = cleanup_data_lifecycle("DNS_OBSERVATIONS", path, NOW)
    assert result == {
        "data_class": "DNS_OBSERVATIONS", "evaluated_at": "2026-10-17T12:00:00Z",
        "eligible_before": 105, "deleted_count": 100, "protected_count": 0,
        "remaining_eligible": 5, "batch_limit": 100,
    }
    assert "id" not in json.dumps(result) and "example.test" not in json.dumps(result)
    # Oldest deadlines were removed first; the five newest expired rows remain.
    with get_connection(path) as connection:
        rows = connection.execute("SELECT external_event_id FROM dns_observations ORDER BY id").fetchall()
        assert len(rows) == 7
        assert {row[0] for row in rows} == {"expired-100", "expired-101", "expired-102", "expired-103", "expired-104", "future", "malformed"}
    repeated = cleanup_data_lifecycle("DNS_OBSERVATIONS", path, NOW)
    assert repeated["deleted_count"] == 5
    assert cleanup_data_lifecycle("DNS_OBSERVATIONS", path, NOW)["deleted_count"] == 0


def test_web_cleanup_preserves_detection_snapshot_and_review_link(lifecycle_context):
    path = lifecycle_context["path"]
    observation_id = insert_web(path, (NOW - timedelta(days=1)).isoformat(), "reviewed", make_detection=True)
    with get_connection(path) as connection:
        connection.row_factory = __import__('sqlite3').Row
        detection = connection.execute("SELECT id, structured_evidence FROM web_detections").fetchone()
        connection.execute("INSERT INTO incident_reviews (incident_key,title,summary,state,priority,confidence,created_at,updated_at,disposition) VALUES ('review-key','Review','', 'OPEN','MEDIUM','MEDIUM',?,?, 'UNREVIEWED')", (NOW.isoformat(), NOW.isoformat()))
        review_id = connection.execute("SELECT id FROM incident_reviews").fetchone()[0]
        connection.execute("INSERT INTO incident_review_evidence (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,'WEB_DETECTION',?,?,?)", (review_id, detection["id"], NOW.isoformat(), NOW.isoformat()))
    result = cleanup_data_lifecycle("WEB_OBSERVATIONS", path, NOW)
    assert result["deleted_count"] == 1
    with get_connection(path) as connection:
        connection.row_factory = __import__('sqlite3').Row
        current = connection.execute("SELECT primary_observation_id, structured_evidence FROM web_detections WHERE id=?", (detection["id"],)).fetchone()
        assert current["primary_observation_id"] is None
        assert current["structured_evidence"] == detection["structured_evidence"]
        assert connection.execute("SELECT observation_id FROM web_detection_observations WHERE detection_id=?", (detection["id"],)).fetchone()[0] is None
        assert connection.execute("SELECT COUNT(*) FROM incident_review_evidence WHERE incident_id=? AND evidence_type='WEB_DETECTION' AND evidence_id=?", (review_id, detection["id"])).fetchone()[0] == 1


def test_web_cleanup_protects_unsafe_snapshot_once_and_recomputes(lifecycle_context):
    path = lifecycle_context["path"]
    obs = insert_web(path, (NOW - timedelta(days=2)).isoformat(), "unsafe", make_detection=True, invalid_snapshot=True)
    with get_connection(path) as connection:
        det_id = connection.execute("SELECT id FROM web_detections").fetchone()[0]
    insert_web(path, (NOW + timedelta(days=1)).isoformat(), "future")
    insert_web(path, "invalid-date", "bad")
    result = cleanup_data_lifecycle("WEB_OBSERVATIONS", path, NOW)
    assert result["eligible_before"] == 0
    assert result["deleted_count"] == 0
    assert result["protected_count"] == 1
    assert result["remaining_eligible"] == 0
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM web_observations WHERE id=?", (obs,)).fetchone()[0] == 1


def test_cleanup_trigger_failure_rolls_back_whole_batch(lifecycle_context):
    path = lifecycle_context["path"]
    ids = [insert_dns(path, (NOW - timedelta(days=1)).isoformat(), f"rollback-{i}") for i in range(3)]
    with get_connection(path) as connection:
        connection.execute("CREATE TRIGGER fail_cleanup BEFORE DELETE ON dns_observations WHEN OLD.id = %d BEGIN SELECT RAISE(ABORT, 'forced'); END" % ids[1])
    with pytest.raises(Exception):
        cleanup_data_lifecycle("DNS_OBSERVATIONS", path, NOW)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dns_observations WHERE id IN (?,?,?)", ids).fetchone()[0] == 3


def test_cleanup_rejects_unapproved_class_and_schema_stays_46(lifecycle_context):
    with pytest.raises(ValueError):
        cleanup_data_lifecycle("EVENTS", lifecycle_context["path"], NOW)
    with get_connection(lifecycle_context["path"]) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46


def test_legacy_event_preview_uses_local_wall_clock_and_classifies_rows(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    insert_legacy_event(path, (cutoff + timedelta(seconds=1)).isoformat(), username=None)
    insert_legacy_event(path, cutoff.isoformat(), message="at cutoff")
    insert_legacy_event(path, (cutoff - timedelta(seconds=1)).isoformat(), message="older")
    insert_legacy_event(path, (local_now + timedelta(seconds=1)).isoformat(), message="future")
    insert_legacy_event(path, "not-an-iso-time", message="malformed")
    insert_legacy_event(path, cutoff.isoformat(), severity="CRITICAL", message="bad enum")

    result = preview_data_lifecycle(path, NOW)
    item = get_item(result, "LEGACY_EVENTS")
    assert item["retention_days"] == 90
    assert item["evaluated_at_local"] == local_now.isoformat()
    assert item["cutoff_at_local"] == cutoff.isoformat()
    assert item["total_rows"] == 6
    assert item["expired_rows"] == 2
    assert item["eligible_rows"] == 2
    assert item["malformed_skipped_rows"] == 2
    assert item["future_skipped_rows"] == 1
    assert item["max_delete_rows"] == 100
    oldest = (cutoff - timedelta(seconds=1)).isoformat()
    assert item["oldest_retained_at"] == oldest
    assert item["oldest_eligible_at"] == oldest


def test_legacy_event_null_username_is_valid_and_exports_see_only_retained_rows(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    expired_id = insert_legacy_event(path, (cutoff - timedelta(seconds=1)).isoformat())
    recent_id = insert_legacy_event(path, local_now.isoformat(), username=None)
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    assert result["deleted_count"] == 1
    assert result["remaining_eligible"] == 0
    rows = get_bounded_export_events(row_limit=5000, db_path=path)
    assert [row["id"] for row in rows] == [recent_id]
    assert expired_id not in {row["id"] for row in rows}


def test_legacy_event_protection_preserves_threat_snapshot_and_review(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    old_time = (local_now - timedelta(days=120)).isoformat()
    protected_id = insert_legacy_event(path, old_time, message="protected source")
    threat_id, snapshot = protect_legacy_event(path, protected_id)
    with get_connection(path) as connection:
        connection.execute(
            """INSERT INTO incident_reviews (
                incident_key,title,summary,state,priority,confidence,created_at,updated_at,disposition
            ) VALUES ('retention-review','Review','', 'OPEN','MEDIUM','MEDIUM',?,?, 'UNREVIEWED')""",
            (NOW.isoformat(), NOW.isoformat()),
        )
        review_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
        connection.execute(
            """INSERT INTO incident_review_evidence(
                incident_id,evidence_type,evidence_id,observed_at,added_at
            ) VALUES (?,'THREAT_DETECTION',?,?,?)""",
            (review_id, threat_id, NOW.isoformat(), NOW.isoformat()),
        )
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    assert result["deleted_count"] == 0
    assert result["eligible_before"] == 0
    assert result["protected_count"] == 1
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events WHERE id=?", (protected_id,)).fetchone()[0] == 1
        row = connection.execute(
            "SELECT ssh_event_id,evidence_snapshot FROM threat_evidence WHERE threat_id=?", (threat_id,)
        ).fetchone()
        assert tuple(row) == (protected_id, snapshot)
    from database.incident_review_reports import build_incident_review_report
    report = build_incident_review_report(review_id, NOW.isoformat(), path)
    assert report["evidence"]["items"][0]["source_status"] == "AVAILABLE"


@pytest.mark.parametrize("eligible_count", [0, 3, 100, 101, 205])
def test_legacy_event_cleanup_deletes_one_oldest_first_batch(lifecycle_context, eligible_count):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    created = []
    # Reverse insertion order to prove selection follows timestamp, then ID.
    for index in reversed(range(eligible_count)):
        event_time = cutoff - timedelta(seconds=index)
        created.append((event_time, insert_legacy_event(path, event_time.isoformat(), message=str(index))))
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    expected_deleted = min(eligible_count, 100)
    assert result["deleted_count"] == expected_deleted
    assert result["remaining_eligible"] == eligible_count - expected_deleted
    assert result["batch_limit"] == 100
    with get_connection(path) as connection:
        remaining = {row[0] for row in connection.execute("SELECT id FROM events")}
    expected_removed = {
        event_id for _, event_id in sorted(created, key=lambda item: (item[0], item[1]))[:expected_deleted]
    }
    assert remaining == {event_id for _, event_id in created} - expected_removed


def test_legacy_event_cleanup_uses_id_ascending_for_equal_timestamps(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    event_ids = [insert_legacy_event(path, cutoff.isoformat()) for _ in range(101)]
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    assert result["deleted_count"] == 100
    with get_connection(path) as connection:
        remaining = [row[0] for row in connection.execute("SELECT id FROM events ORDER BY id")]
    assert remaining == [event_ids[-1]]


def test_legacy_event_cleanup_preserves_malformed_future_and_recent_rows(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    malformed = insert_legacy_event(path, "bad timestamp")
    future = insert_legacy_event(path, (local_now + timedelta(days=1)).isoformat())
    recent = insert_legacy_event(path, (cutoff + timedelta(seconds=1)).isoformat())
    invalid_field = insert_legacy_event(path, cutoff.isoformat(), event_type="UNEXPECTED")
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    assert result["deleted_count"] == 0
    assert result["malformed_skipped_rows"] == 2
    assert result["future_skipped_rows"] == 1
    with get_connection(path) as connection:
        remaining = {row[0] for row in connection.execute("SELECT id FROM events")}
    assert remaining == {malformed, future, recent, invalid_field}


def test_legacy_event_cleanup_skips_invalid_required_storage_types(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    old_time = (local_now - timedelta(days=100)).isoformat()
    with get_connection(path) as connection:
        blob_ip = connection.execute(
            """INSERT INTO events(timestamp,source_ip,username,event_type,severity,message,event_count)
               VALUES(?,?,NULL,'LOGIN_FAILED','WARNING','message',1)""",
            (old_time, sqlite3.Binary(b"192.0.2.8")),
        ).lastrowid
        real_count = connection.execute(
            """INSERT INTO events(timestamp,source_ip,username,event_type,severity,message,event_count)
               VALUES(?,'192.0.2.8',NULL,'LOGIN_FAILED','WARNING','message',1.5)""",
            (old_time,),
        ).lastrowid
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    assert result["deleted_count"] == 0
    assert result["malformed_skipped_rows"] == 2
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events WHERE id IN (?,?)", (blob_ip, real_count)).fetchone()[0] == 2


def test_legacy_classifier_byte_bounds_text_with_embedded_nul(lifecycle_context):
    path = lifecycle_context["path"]
    event_id = insert_legacy_event(path, "2026-01-01T00:00:00")
    with get_connection(path) as connection:
        connection.execute(
            "UPDATE events SET timestamp=? WHERE id=?",
            ("2026-01-01T00:00:00\x00" + "x" * 4096, event_id),
        )
        connection.execute(
            "UPDATE events SET source_ip=? WHERE id=?",
            ("127.0.0.1\x00" + "x" * 4096, event_id),
        )
        connection.row_factory = sqlite3.Row
        from database.data_lifecycle import _LEGACY_EVENT_CLASSIFICATION_SQL
        row = connection.execute(_LEGACY_EVENT_CLASSIFICATION_SQL).fetchone()
        assert row["timestamp_value"] is None
        assert row["source_ip_value"] is None
    item = get_item(preview_data_lifecycle(path, NOW), "LEGACY_EVENTS")
    assert item["malformed_skipped_rows"] == 1
    result = cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    assert result["deleted_count"] == 0
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events WHERE id=?", (event_id,)).fetchone()[0] == 1


def test_legacy_event_delete_failure_rolls_back_entire_batch(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    ids = [insert_legacy_event(path, (cutoff - timedelta(seconds=i)).isoformat()) for i in range(3)]
    with get_connection(path) as connection:
        connection.execute(
            """CREATE TRIGGER fail_legacy_delete BEFORE DELETE ON events
               WHEN OLD.id = %d BEGIN SELECT RAISE(ABORT, 'forced'); END""" % ids[1]
        )
    with pytest.raises(sqlite3.IntegrityError):
        cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events WHERE id IN (?,?,?)", ids).fetchone()[0] == 3


def test_legacy_event_cleanup_serializes_a_concurrent_insert(lifecycle_context, monkeypatch):
    import database.data_lifecycle as lifecycle
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    expired_id = insert_legacy_event(path, (cutoff - timedelta(days=1)).isoformat())
    selected = threading.Event()
    resume = threading.Event()
    classify = lifecycle._classify_legacy_events

    def pause_after_selection(connection, evaluated_at, *, select_limit=0):
        result = classify(connection, evaluated_at, select_limit=select_limit)
        selected.set()
        if not resume.wait(timeout=5):
            raise AssertionError("cleanup synchronization timed out")
        return result

    monkeypatch.setattr(lifecycle, "_classify_legacy_events", pause_after_selection)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(cleanup_data_lifecycle, "LEGACY_EVENTS", path, NOW)
        try:
            assert selected.wait(timeout=5)
            competing = sqlite3.connect(path, timeout=0)
            try:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    competing.execute(
                        """INSERT INTO events(timestamp,source_ip,event_type,severity,message,event_count)
                           VALUES(?,?,?,?,?,?)""",
                        (local_now.isoformat(), "192.0.2.9", "SSH_PREAUTH", "INFO", "current", 1),
                    )
            finally:
                competing.close()
        finally:
            resume.set()
        result = future.result(timeout=5)
    assert result["deleted_count"] == 1
    current_id = insert_legacy_event(path, local_now.isoformat(), message="new current event")
    with get_connection(path) as connection:
        remaining = {row[0] for row in connection.execute("SELECT id FROM events")}
    assert expired_id not in remaining
    assert current_id in remaining


def test_legacy_event_cleanup_lock_failure_is_closed_and_safe(lifecycle_context, monkeypatch):
    import database.data_lifecycle as lifecycle
    path = lifecycle_context["path"]
    blocker = sqlite3.connect(path, timeout=0)
    blocker.execute("BEGIN IMMEDIATE")
    monkeypatch.setattr(lifecycle, "get_connection", lambda db_path: sqlite3.connect(db_path, timeout=0))
    try:
        with pytest.raises(sqlite3.OperationalError):
            cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    finally:
        blocker.rollback()
        blocker.close()


def test_legacy_event_cleanup_audit_is_not_mislabeled_and_schema_stays_46(lifecycle_context):
    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    cutoff = local_now - timedelta(days=90)
    insert_legacy_event(path, (cutoff - timedelta(seconds=1)).isoformat())
    cleanup_data_lifecycle("LEGACY_EVENTS", path, NOW)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute(
            "SELECT COUNT(*) FROM management_audit_events WHERE event_type='DATA_LIFECYCLE_CLEANUP_EXECUTED'"
        ).fetchone()[0] == 0


def test_dns_cleanup_uses_inclusive_boundary_and_one_clock(lifecycle_context, monkeypatch):
    path = lifecycle_context["path"]
    insert_dns(path, NOW.isoformat(), "exact-boundary")
    import database.data_lifecycle as lifecycle
    calls = []
    monkeypatch.setattr(lifecycle, "_utc_now", lambda: calls.append(1) or NOW)
    result = cleanup_data_lifecycle("DNS_OBSERVATIONS", path)
    assert result["deleted_count"] == 1
    assert result["evaluated_at"] == "2026-10-17T12:00:00Z"
    assert calls == [1]


def test_cleanup_route_is_direct_local_strict_and_no_store(lifecycle_context):
    route = next(route for route in lifecycle_context["app"].routes
                 if getattr(route, "path", None) == "/data-lifecycle/cleanup")
    assert "POST" in route.methods
    assert any(dependency.dependency is local_management for dependency in route.dependencies)
    with pytest.raises(Exception):
        CleanupRequest.model_validate({"data_class": "DNS_OBSERVATIONS", "batch_size": 1})
    request = Request({
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/data-lifecycle/cleanup", "raw_path": b"/data-lifecycle/cleanup",
        "query_string": b"", "root_path": "", "headers": [(b"host", b"127.0.0.1")],
        "client": ("127.0.0.1", 5050), "server": ("127.0.0.1", 8000),
    })
    response = Response()
    body = CleanupRequest(data_class="DNS_OBSERVATIONS")
    local_management(request, response)
    result = route.endpoint(request=request, response=response, body=body)
    assert response.headers["cache-control"] == "no-store"
    assert result["deleted_count"] == 0

    path = lifecycle_context["path"]
    local_now = NOW.astimezone().replace(tzinfo=None)
    insert_legacy_event(path, (local_now - timedelta(days=91)).isoformat())
    response = Response()
    local_management(request, response)
    result = route.endpoint(
        request=request, response=response, body=CleanupRequest(data_class="LEGACY_EVENTS")
    )
    assert response.headers["cache-control"] == "no-store"
    assert result["data_class"] == "LEGACY_EVENTS"
    assert result["deleted_count"] == 1
    assert result["batch_limit"] == 100
