import json
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request

from api.data_lifecycle import CleanupRequest, register_data_lifecycle_routes
from api.remote_sensors import local_management
from database.data_lifecycle import cleanup_data_lifecycle, preview_data_lifecycle
from database.db import get_connection, initialize_database
from database.perimeter_lifecycle import (
    PERIMETER_MAX_COMPONENTS_PER_APPLY,
    PERIMETER_RETENTION_DAYS,
)
from database.perimeter import persist_perimeter_event
from services.perimeter_models import PerimeterEvent


NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=PERIMETER_RETENTION_DAYS)


@pytest.fixture
def perimeter_db(tmp_path):
    path = tmp_path / "perimeter-lifecycle.db"
    initialize_database(path)
    with get_connection(path) as connection:
        site_id = connection.execute(
            "INSERT INTO sites(name,enabled,created_at,updated_at) VALUES('Lifecycle site',1,?,?)",
            (NOW.isoformat(), NOW.isoformat()),
        ).lastrowid
    return path, site_id


def add_event(connection, site_id, received_at, *, observed_at=None, external_id=None):
    return connection.execute(
        """INSERT INTO perimeter_events (
            external_event_id,site_id,sensor_id,source_type,source_key,event_type,
            direction,action,protocol,source_ip,destination_ip,destination_port,
            observed_at,received_at
        ) VALUES(?,?,NULL,'FIREWALL','edge-fw','CONNECTION_ATTEMPT',
            'INBOUND','BLOCK','TCP','203.0.113.20','192.0.2.10',22,?,?)""",
        (external_id or f"event-{received_at}-{connection.total_changes}", site_id,
         (observed_at or OLD).isoformat() if isinstance(observed_at or OLD, datetime) else observed_at,
         received_at.isoformat() if isinstance(received_at, datetime) else received_at),
    ).lastrowid


def add_detection(connection, site_id, event_ids, *, primary=None):
    primary = primary or event_ids[0]
    detection_type = "INBOUND_ATTEMPT" if len(event_ids) == 1 else "REPEATED_INBOUND_ATTEMPTS"
    return connection.execute(
        """INSERT INTO perimeter_detections (
            stable_key,detection_type,state,confidence,site_id,sensor_id,primary_event_id,
            event_ids_json,source_ip,destination_ip,destination_port,protocol,action,
            event_count,unique_source_count,first_seen,last_seen,rule_id,rule_version,reason,created_at
        ) VALUES(?,?,'REVIEW','HIGH',?,NULL,?,?, '203.0.113.20','192.0.2.10',22,
            'TCP','BLOCK',?,1,?,?, 'retention-test','1','test evidence',?)""",
        (f"detection-{primary}", detection_type, site_id, primary,
         json.dumps(event_ids), len(event_ids), OLD.isoformat(), OLD.isoformat(), NOW.isoformat()),
    ).lastrowid


def add_policy(connection, site_id, event_ids, allowed, blocked, *, primary=None):
    primary = primary or event_ids[0]
    action = "ALLOW" if primary in allowed else "BLOCK"
    return connection.execute(
        """INSERT INTO perimeter_policy_correlations (
            stable_key,correlation_type,state,confidence,site_id,sensor_id,primary_event_id,
            event_ids_json,allowed_event_ids_json,blocked_event_ids_json,source_type,source_key,
            source_ip,destination_ip,destination_port,protocol,primary_action,event_count,
            allow_count,blocked_count,first_seen,last_seen,rule_id,rule_version,reason,created_at
        ) VALUES(?,'BLOCK_THEN_ALLOW','REVIEW','HIGH',?,NULL,?,?,?,?, 'FIREWALL','edge-fw',
            '203.0.113.20','192.0.2.10',22,'TCP',?,?,?,?,?,?, 'retention-test','1','test evidence',?)""",
        (f"policy-{primary}", site_id, primary, json.dumps(event_ids), json.dumps(allowed),
         json.dumps(blocked), action, len(event_ids), len(allowed), len(blocked),
         OLD.isoformat(), OLD.isoformat(), NOW.isoformat()),
    ).lastrowid


def add_host_correlation(path, site_id, event_id):
    # The graph test needs a host row tied to an event. Other inventory foreign
    # keys are outside this lifecycle fixture, so seed those fields with FK checks
    # disabled; the actual event/site references remain valid and cleanup reopens
    # the database with foreign keys enabled.
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        cursor = connection.execute(
            """INSERT INTO perimeter_host_correlations (
                stable_key,correlation_type,state,confidence,site_id,sensor_id,event_id,
                scope_id,network_id,device_id,destination_ip,destination_port,protocol,action,
                observed_at,device_last_seen,device_status,identity_confidence,rule_id,
                rule_version,reason,created_at
            ) VALUES(?,'DESTINATION_DEVICE_MATCH','REVIEW','HIGH',?,NULL,?,1,1,1,
                '192.0.2.10',22,'TCP','BLOCK',?,?, 'ONLINE','HIGH','test','1','test',?)""",
            (f"host-{event_id}", site_id, event_id, OLD.isoformat(), OLD.isoformat(), NOW.isoformat()),
        )
        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def add_incident(connection):
    return connection.execute(
        """INSERT INTO incident_reviews (
            incident_key,title,state,priority,confidence,created_at,updated_at,disposition
        ) VALUES('IR-retention-test','Retention test','OPEN','MEDIUM','MEDIUM',?,?, 'UNREVIEWED')""",
        (NOW.isoformat(), NOW.isoformat()),
    ).lastrowid


def add_current_reference(connection, incident_id, evidence_type, evidence_id):
    return connection.execute(
        """INSERT INTO incident_review_evidence
           (incident_id,evidence_type,evidence_id,observed_at,added_at)
           VALUES(?,?,?,?,?)""",
        (incident_id, evidence_type, evidence_id, OLD.isoformat(), NOW.isoformat()),
    ).lastrowid


def add_timeline_reference(connection, incident_id, event_type, evidence_type, evidence_id):
    return connection.execute(
        """INSERT INTO incident_review_events
           (incident_review_id,event_type,actor_source,created_at,evidence_type,evidence_id,summary)
           VALUES(?,?,'OPERATOR',?,?,?,'Historical evidence relation')""",
        (incident_id, event_type, NOW.isoformat(), evidence_type, evidence_id),
    ).lastrowid


def item(path, evaluated_at=NOW):
    return next(entry for entry in preview_data_lifecycle(path, evaluated_at)["items"]
                if entry["data_class"] == "PERIMETER_EVIDENCE")


def table_counts(path):
    with get_connection(path) as connection:
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("perimeter_events", "perimeter_detections",
                                   "perimeter_policy_correlations", "perimeter_host_correlations"))


def test_cutoff_is_inclusive_and_uses_server_received_at(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        exact = add_event(connection, site_id, OLD, observed_at=NOW)
        older = add_event(connection, site_id, OLD - timedelta(microseconds=1), observed_at=NOW)
        newer = add_event(connection, site_id, OLD + timedelta(microseconds=1), observed_at=OLD - timedelta(days=500))
    preview = item(path)
    assert preview["eligible_components"] == 2
    assert preview["eligible_events"] == 2
    assert preview["newer_components"] == 1
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["events_deleted"] == 2
    with get_connection(path) as connection:
        remaining = {row[0] for row in connection.execute("SELECT id FROM perimeter_events")}
    assert remaining == {newer}
    assert exact != older


@pytest.mark.parametrize("bad_time", ["not-a-time", "2026-01-01T00:00:00", (NOW + timedelta(seconds=1)).isoformat()])
def test_malformed_naive_and_future_received_at_are_preserved(perimeter_db, bad_time):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        add_event(connection, site_id, bad_time)
    summary = item(path)
    assert summary["eligible_components"] == 0
    assert summary["malformed_or_future_events"] == 1
    assert summary["ambiguous_components"] == 1
    assert cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)["events_deleted"] == 0
    assert table_counts(path)[0] == 1


def test_invalid_utf8_received_at_is_preserved_as_malformed(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        event_id = add_event(connection, site_id, OLD)
        connection.execute(
            "UPDATE perimeter_events SET received_at=CAST(X'FF' AS TEXT) WHERE id=?",
            (event_id,),
        )
    summary = item(path)
    assert summary["eligible_components"] == 0
    assert summary["malformed_or_future_events"] == 1
    assert cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)["events_deleted"] == 0


def test_offset_aware_received_at_normalizes_to_utc(perimeter_db):
    path, site_id = perimeter_db
    equivalent = OLD.astimezone(timezone(timedelta(hours=2))).isoformat()
    with get_connection(path) as connection:
        add_event(connection, site_id, equivalent)
    summary = item(path)
    assert summary["eligible_components"] == 1
    assert summary["oldest_eligible_received_at"] == OLD.isoformat().replace("+00:00", "Z")


def test_transitive_detection_policy_component_deletes_atomically(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD - timedelta(days=index)) for index in range(6)]
        detection = add_detection(connection, site_id, ids[:5], primary=ids[0])
        policy = add_policy(connection, site_id, ids[4:6], [ids[4]], [ids[5]], primary=ids[4])
    summary = item(path)
    assert summary["total_components"] == 1
    assert summary["largest_eligible_component_events"] == 6
    assert summary["largest_eligible_component_derived_rows"] == 2
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["components_deleted"] == 1
    assert result["events_deleted"] == 6
    assert result["detections_deleted"] == result["policy_correlations_deleted"] == 1
    assert table_counts(path) == (0, 0, 0, 0)
    assert detection > 0 and policy > 0


def test_long_chain_larger_than_membership_width_remains_one_atomic_component(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD - timedelta(seconds=index)) for index in range(601)]
        for start in range(0, len(ids) - 4, 4):
            add_detection(connection, site_id, ids[start:start + 5], primary=ids[start])
    summary = item(path)
    assert summary["total_components"] == 1
    assert summary["largest_eligible_component_events"] == 601
    assert summary["largest_eligible_component_derived_rows"] == 150
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["components_deleted"] == 1
    assert result["events_deleted"] == 601
    assert result["detections_deleted"] == 150
    assert result["largest_selected_component_events"] == 601
    assert result["largest_selected_component_derived_rows"] == 150
    assert result["largest_selected_component_total_rows"] == 751
    assert table_counts(path) == (0, 0, 0, 0)


def test_newer_root_preserves_entire_derived_component(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD if index < 4 else OLD + timedelta(seconds=1))
               for index in range(5)]
        add_detection(connection, site_id, ids)
    preview = item(path)
    assert preview["eligible_components"] == 0
    assert preview["newer_components"] == 1
    assert cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)["components_deleted"] == 0
    assert table_counts(path) == (5, 1, 0, 0)


def test_host_correlation_is_in_component_and_deleted_before_event(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        event_id = add_event(connection, site_id, OLD)
    host_id = add_host_correlation(path, site_id, event_id)
    assert item(path)["eligible_host_correlations"] == 1
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["host_correlations_deleted"] == 1
    assert result["events_deleted"] == 1
    assert table_counts(path) == (0, 0, 0, 0)
    assert host_id > 0


@pytest.mark.parametrize("historical_type", ["EVIDENCE_ATTACHED", "EVIDENCE_DETACHED"])
def test_current_and_historical_incident_references_protect_whole_component(perimeter_db, historical_type):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD - timedelta(days=index)) for index in range(5)]
        detection = add_detection(connection, site_id, ids, primary=ids[0])
        policy = add_policy(connection, site_id, ids[3:5], [ids[3]], [ids[4]], primary=ids[3])
        incident_id = add_incident(connection)
        if historical_type == "EVIDENCE_ATTACHED":
            add_timeline_reference(connection, incident_id, historical_type, "PERIMETER_POLICY_CORRELATION", policy)
        else:
            add_current_reference(connection, incident_id, "PERIMETER_DETECTION", detection)
            add_timeline_reference(connection, incident_id, historical_type, "PERIMETER_POLICY_CORRELATION", policy)
    summary = item(path)
    assert summary["protected_components"] == 1
    assert summary["eligible_components"] == 0
    assert summary["largest_protected_component_total_rows"] == 7
    assert cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)["components_deleted"] == 0
    assert table_counts(path) == (5, 1, 1, 0)


def test_missing_incident_source_globally_blocks_without_partial_deletion(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        event_id = add_event(connection, site_id, OLD)
        incident_id = add_incident(connection)
        add_current_reference(connection, incident_id, "PERIMETER_DETECTION", 99999)
    summary = item(path)
    assert summary["cleanup_blocked"] is True
    assert summary["ambiguous_references"] == 1
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["cleanup_blocked"] is True
    assert result["components_deleted"] == result["events_deleted"] == 0
    assert table_counts(path) == (1, 0, 0, 0)
    assert event_id > 0


def test_malformed_membership_json_global_blocks_cleanup(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD) for _ in range(5)]
        detection = add_detection(connection, site_id, ids)
        connection.execute("UPDATE perimeter_detections SET event_ids_json='{' WHERE id=?", (detection,))
    summary = item(path)
    assert summary["cleanup_blocked"] is True
    assert summary["graph_anomalies"] == 1
    assert summary["eligible_components"] == 0
    assert cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)["events_deleted"] == 0
    assert table_counts(path) == (5, 1, 0, 0)


def test_missing_event_membership_globally_blocks_cleanup(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD) for _ in range(5)]
        detection = add_detection(connection, site_id, ids)
        connection.execute(
            "UPDATE perimeter_detections SET event_ids_json=? WHERE id=?",
            (json.dumps(ids[:4] + [999999]), detection),
        )
    assert item(path)["cleanup_blocked"] is True
    assert cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)["events_deleted"] == 0
    assert table_counts(path) == (5, 1, 0, 0)


def test_apply_rechecks_incident_reference_added_after_preview(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD) for _ in range(5)]
        detection_id = add_detection(connection, site_id, ids)
    assert item(path)["eligible_components"] == 1
    with get_connection(path) as connection:
        incident_id = add_incident(connection)
        add_current_reference(connection, incident_id, "PERIMETER_DETECTION", detection_id)
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["components_deleted"] == 0
    assert table_counts(path) == (5, 1, 0, 0)


def test_apply_rolls_back_all_children_if_a_later_delete_fails(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD) for _ in range(5)]
        add_detection(connection, site_id, ids)
    add_host_correlation(path, site_id, ids[0])
    with get_connection(path) as connection:
        connection.execute(
            """CREATE TRIGGER fail_perimeter_detection_delete
               BEFORE DELETE ON perimeter_detections
               BEGIN SELECT RAISE(ABORT,'injected failure'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError):
        cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert table_counts(path) == (5, 1, 0, 1)


def test_classifier_and_delete_stay_inside_apply_transaction(perimeter_db, monkeypatch):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        add_event(connection, site_id, OLD)
    import database.data_lifecycle as lifecycle
    original = lifecycle.apply_perimeter_evidence_cleanup
    observed = []

    def check_transaction(connection, evaluated_at):
        observed.append(connection.in_transaction)
        return original(connection, evaluated_at)

    monkeypatch.setattr(lifecycle, "apply_perimeter_evidence_cleanup", check_transaction)
    cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert observed == [True]


def test_apply_deletes_only_25_oldest_components(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        ids = [add_event(connection, site_id, OLD - timedelta(days=index)) for index in range(30)]
    preview = item(path)
    assert preview["eligible_components"] == 30
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert PERIMETER_MAX_COMPONENTS_PER_APPLY == 25
    assert result["components_deleted"] == 25
    assert result["events_deleted"] == 25
    with get_connection(path) as connection:
        remaining = [row[0] for row in connection.execute("SELECT id FROM perimeter_events ORDER BY id")]
    assert remaining == ids[:5]


def test_zero_eligible_apply_is_a_successful_noop(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        add_event(connection, site_id, OLD + timedelta(days=1))
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["components_deleted"] == result["events_deleted"] == 0
    assert table_counts(path) == (1, 0, 0, 0)


def test_ten_thousand_singletons_classify_with_batch_reader_shape(perimeter_db):
    path, site_id = perimeter_db
    with get_connection(path) as connection:
        connection.executemany(
            """INSERT INTO perimeter_events (
                external_event_id,site_id,source_type,source_key,event_type,direction,
                action,protocol,source_ip,destination_ip,destination_port,observed_at,received_at
            ) VALUES(? ,?,'FIREWALL','scale','CONNECTION_ATTEMPT','INBOUND','BLOCK','TCP',
                '203.0.113.20','192.0.2.10',22,?,?)""",
            ((f"scale-{index}", site_id, OLD.isoformat(), OLD.isoformat()) for index in range(10_000)),
        )
    summary = item(path)
    assert summary["events_classified"] == 10_000
    assert summary["total_components"] == summary["eligible_components"] == 10_000
    assert summary["eligible_events"] == 10_000
    source = __import__("inspect").getsource(__import__("database.perimeter_lifecycle", fromlist=["x"]))
    assert ".fetchmany(" in source
    assert ".fetchall(" not in source
    assert "parent =" not in source and "rank =" not in source


def test_redelivered_identity_after_cleanup_is_new_receipt(perimeter_db):
    path, site_id = perimeter_db
    observed = OLD - timedelta(days=500)
    with get_connection(path) as connection:
        event_id = add_event(connection, site_id, OLD, observed_at=observed, external_id="replay-id")
    result = cleanup_data_lifecycle("PERIMETER_EVIDENCE", path, NOW)
    assert result["events_deleted"] == 1
    event = PerimeterEvent(
        external_event_id="replay-id", site_id=site_id, source_type="FIREWALL",
        source_key="edge-fw", observed_at=observed, event_type="CONNECTION_ATTEMPT",
        direction="INBOUND", action="BLOCK", protocol="TCP", source_ip="203.0.113.20",
        destination_ip="192.0.2.10", destination_port=22,
    )
    inserted = persist_perimeter_event(event, path)
    assert inserted["id"] != event_id
    assert datetime.fromisoformat(inserted["received_at"]) > NOW - timedelta(days=PERIMETER_RETENTION_DAYS)


def test_cleanup_api_requires_local_management_and_explicit_perimeter_confirmation(perimeter_db):
    path, _ = perimeter_db
    app = FastAPI()
    register_data_lifecycle_routes(app, lambda: path)
    route = next(route for route in app.routes
                 if getattr(route, "path", None) == "/data-lifecycle/cleanup")
    assert any(dependency.dependency is local_management for dependency in route.dependencies)
    with pytest.raises(Exception):
        CleanupRequest.model_validate({"data_class": "PERIMETER_EVIDENCE", "confirmed": True, "cutoff": "x"})
    unconfirmed_body = CleanupRequest.model_validate({"data_class": "PERIMETER_EVIDENCE"})
    assert unconfirmed_body.confirmed is None
    request = Request({
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/data-lifecycle/cleanup",
        "raw_path": b"/data-lifecycle/cleanup", "query_string": b"", "root_path": "",
        "headers": [(b"host", b"127.0.0.1")], "client": ("127.0.0.1", 5050),
        "server": ("127.0.0.1", 8000),
    })
    response = Response()
    local_management(request, response)
    with pytest.raises(HTTPException) as error:
        route.endpoint(request=request, response=response, body=unconfirmed_body)
    assert error.value.status_code == 422
    result = route.endpoint(
        request=request, response=response,
        body=CleanupRequest(data_class="PERIMETER_EVIDENCE", confirmed=True),
    )
    assert result["data_class"] == "PERIMETER_EVIDENCE"
    for headers in (
        {"authorization": "Bearer sensor"},
        {"x-sentinelip-sensor-token": "sensor"},
        {"x-sentinelip-sensor-id": "1"},
        {"x-sensor-uuid": "sensor"},
    ):
        denied = Request({
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "POST", "scheme": "http", "path": "/data-lifecycle/cleanup",
            "raw_path": b"/data-lifecycle/cleanup", "query_string": b"", "root_path": "",
            "headers": [(b"host", b"127.0.0.1"), *[(k.encode(), v.encode()) for k, v in headers.items()]],
            "client": ("127.0.0.1", 5050), "server": ("127.0.0.1", 8000),
        })
        with pytest.raises(HTTPException) as error:
            local_management(denied, Response())
        assert error.value.status_code == 403
