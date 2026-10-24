from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.management_audit import register_management_audit_routes
from database.db import get_connection, initialize_database
from database.management_audit import record_event


def client_for(path, *, address="127.0.0.1", host="http://127.0.0.1"):
    app = FastAPI()
    register_management_audit_routes(app, lambda: path)
    return TestClient(app, base_url=host, client=(address, 4321))


def seed_events(path):
    with get_connection(path) as connection:
        record_event(connection, event_type="SITE_CREATED", entity_type="SITE", entity_id=7,
                     site_id=7, actor_type="LOCAL_OPERATOR", new_state="ENABLED")
        record_event(connection, event_type="NETWORK_DELETED", entity_type="NETWORK", entity_id=91,
                     actor_type="API_CLIENT", previous_state="DISABLED")
        record_event(connection, event_type="SENSOR_SCOPE_UNASSIGNED", entity_type="SENSOR_SCOPE_ASSIGNMENT",
                     entity_id="12:33", site_id=7, scope_id=33, sensor_id=12,
                     actor_type="LOCAL_OPERATOR", previous_state="ASSIGNED", new_state="UNASSIGNED")
        record_event(connection, event_type="EXPOSURE_POLICY_REMOVED", entity_type="EXTERNAL_EXPOSURE_POLICY",
                     entity_id=55, scope_id=55, actor_type="API_CLIENT", previous_expected_tcp_ports=[443, 80])
        record_event(connection, event_type="DATA_LIFECYCLE_CLEANUP_EXECUTED", entity_type="DATA_LIFECYCLE",
                     entity_id="DATA_LIFECYCLE", actor_type="LOCAL_OPERATOR",
                     cleanup_data_class="WEB_OBSERVATIONS", cleanup_evaluated_at="2026-10-01T00:00:00Z",
                     cleanup_eligible_before=4, cleanup_deleted_count=2, cleanup_protected_count=1,
                     cleanup_remaining_eligible=1, cleanup_batch_limit=100)
        record_event(connection, event_type="SENSOR_TASK_CREATED", entity_type="SENSOR_TASK", entity_id=81,
                     site_id=7, scope_id=33, sensor_id=12, task_type="DISCOVER_NETWORK",
                     actor_type="LOCAL_OPERATOR", new_state="CREATED")
        record_event(connection, event_type="ENROLLMENT_ISSUED", entity_type="SENSOR_ENROLLMENT", entity_id=5,
                     site_id=7, actor_type="LOCAL_OPERATOR", new_state="ISSUED",
                     enrollment_expires_at="2026-10-02T00:00:00Z")


def setup_db(tmp_path):
    path = tmp_path / "management-audit-api.db"
    initialize_database(path)
    seed_events(path)
    return path


def test_local_history_default_projection_pagination_and_no_store(tmp_path):
    path = setup_db(tmp_path)
    client = client_for(path)
    response = client.get("/management-audit-events")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["limit"] == 50 and body["offset"] == 0
    assert body["returned"] == 7 and body["has_more"] is False
    assert [item["id"] for item in body["items"]] == sorted(
        (item["id"] for item in body["items"]), reverse=True
    )
    allowed = {
        "id", "event_type", "entity_type", "entity_id", "site_id", "scope_id", "sensor_id",
        "actor_type", "occurred_at", "previous_state", "new_state", "scope_type",
        "enrollment_expires_at", "task_type", "target_device_id", "previous_expected_tcp_ports",
        "new_expected_tcp_ports", "cleanup_data_class", "cleanup_evaluated_at",
        "cleanup_eligible_before", "cleanup_deleted_count", "cleanup_protected_count",
        "cleanup_remaining_eligible", "cleanup_batch_limit",
    }
    assert all(set(item) == allowed for item in body["items"])
    assert next(i for i in body["items"] if i["event_type"] == "EXPOSURE_POLICY_REMOVED")["previous_expected_tcp_ports"] == [80, 443]
    cleanup = next(i for i in body["items"] if i["event_type"] == "DATA_LIFECYCLE_CLEANUP_EXECUTED")
    assert (cleanup["cleanup_eligible_before"], cleanup["cleanup_deleted_count"], cleanup["cleanup_protected_count"]) == (4, 2, 1)
    task = next(i for i in body["items"] if i["event_type"] == "SENSOR_TASK_CREATED")
    assert task["task_type"] == "DISCOVER_NETWORK" and task["sensor_id"] == 12
    enrollment = next(i for i in body["items"] if i["event_type"] == "ENROLLMENT_ISSUED")
    assert enrollment["enrollment_expires_at"] == "2026-10-02T00:00:00Z"
    assert not any("token" in key or "credential" in key or "payload" in key for item in body["items"] for key in item)


def test_empty_history_returns_bounded_empty_envelope(tmp_path):
    path = tmp_path / "management-audit-empty.db"
    initialize_database(path)
    response = client_for(path).get("/management-audit-events")
    assert response.status_code == 200
    assert response.json() == {"items": [], "limit": 50, "offset": 0, "returned": 0, "has_more": False}


def test_filters_are_exact_composable_and_deleted_entities_remain_visible(tmp_path):
    path = setup_db(tmp_path)
    client = client_for(path)
    result = client.get("/management-audit-events?site_id=7&event_type=SITE_CREATED").json()
    assert result["returned"] == 1 and result["items"][0]["entity_id"] == "7"
    assignment = client.get("/management-audit-events?entity_type=SENSOR_SCOPE_ASSIGNMENT&entity_id=12%3A33").json()
    assert assignment["returned"] == 1
    assert client.get("/management-audit-events?entity_id=7").status_code == 422
    for query in (
        "event_type=BOGUS", "entity_type=BOGUS", "site_id=0", "site_id=abc",
        "limit=101", "limit=-1", "offset=-1", "free_text=x", "event_type=SITE_CREATED&event_type=SITE_DISABLED",
    ):
        assert client.get(f"/management-audit-events?{query}").status_code == 422
    network = client.get("/management-audit-events?entity_type=NETWORK&entity_id=91").json()
    policy = client.get("/management-audit-events?entity_type=EXTERNAL_EXPOSURE_POLICY&entity_id=55").json()
    assert network["items"][0]["event_type"] == "NETWORK_DELETED"
    assert policy["items"][0]["event_type"] == "EXPOSURE_POLICY_REMOVED"


def test_pagination_is_bounded_stable_and_limit_one_hundred(tmp_path):
    path = tmp_path / "management-audit-pages.db"
    initialize_database(path)
    with get_connection(path) as connection:
        for index in range(105):
            connection.execute(
                "INSERT INTO management_audit_events(event_type,entity_type,entity_id,actor_type,occurred_at) VALUES('SITE_CREATED','SITE',?,'LOCAL_OPERATOR','2026-10-01T00:00:00Z')",
                (str(index + 1),),
            )
    client = client_for(path)
    first = client.get("/management-audit-events?limit=100").json()
    second = client.get("/management-audit-events?limit=100&offset=100").json()
    assert first["returned"] == 100 and first["has_more"] is True
    assert second["returned"] == 5 and second["has_more"] is False
    assert [item["id"] for item in first["items"]] == sorted(
        (item["id"] for item in first["items"]), reverse=True
    )
    assert [item["id"] for item in second["items"]] == sorted(
        (item["id"] for item in second["items"]), reverse=True
    )
    assert first["items"][-1]["id"] > second["items"][0]["id"]
    default_page = client.get("/management-audit-events?limit=1").json()
    next_page = client.get("/management-audit-events?limit=1&offset=1").json()
    assert default_page["items"][0]["id"] > next_page["items"][0]["id"]


def test_local_management_guard_and_read_only_state(tmp_path):
    path = setup_db(tmp_path)
    with get_connection(path) as connection:
        before = connection.execute("SELECT COUNT(*) FROM management_audit_events").fetchone()[0]
        version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        triggers = connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'management_audit_events_%'").fetchall()
    assert client_for(path).get("/management-audit-events").status_code == 200
    rejected_headers = (
        {"X-Forwarded-For": "127.0.0.1"}, {"Forwarded": "for=127.0.0.1"},
        {"Authorization": "Bearer x"}, {"X-Sensor-UUID": "x"},
        {"X-SentinelIP-Sensor-ID": "1"}, {"X-SentinelIP-Sensor-Token": "x"},
    )
    for headers in rejected_headers:
        assert client_for(path).get("/management-audit-events", headers=headers).status_code == 403
    assert client_for(path).get("/management-audit-events", headers={"Host": "other.test"}).status_code == 403
    assert client_for(path, address="192.0.2.10").get("/management-audit-events").status_code == 403
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM management_audit_events").fetchone()[0] == before
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == version == 46
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'management_audit_events_%'").fetchall() == triggers
