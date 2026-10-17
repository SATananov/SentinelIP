import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request

from api.data_lifecycle import register_data_lifecycle_routes
from api.remote_sensors import local_management
from database.data_lifecycle import _parse_retention, preview_data_lifecycle
from database.db import get_connection, initialize_database
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
    assert all(set(item) == {
        "data_class", "policy_state", "total_rows", "expired_rows", "eligible_rows",
        "protected_by_review", "protected_by_dependency", "policy_undefined",
        "invalid_retention_rows", "oldest_eligible_at",
    } for item in payload["items"])
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
    assert get_item(result, "LEGACY_EVENTS")["policy_state"] == "POLICY_UNDEFINED"
    assert get_item(result, "LEGACY_EVENTS")["policy_undefined"] == 1
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
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 43
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


def test_schema_remains_43_and_preview_is_read_only(lifecycle_context):
    path = lifecycle_context["path"]
    with get_connection(path) as connection:
        before = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        tables_before = connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    preview_data_lifecycle(path, NOW)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 43
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == before
        assert connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == tables_before
