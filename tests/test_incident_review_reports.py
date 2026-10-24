import json
import re

import pytest
from fastapi import FastAPI, HTTPException

from api.incident_reviews import register_incident_review_routes
from database import incident_review_reports as reports
from database.db import get_connection, initialize_database
from database.incident_reviews import create_review, update_review
from database.inventory import create_device, create_scope_device
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.scopes import create_scope


REPORT_AT = "2026-10-18T12:34:56Z"
BASE_EVIDENCE_KEYS = {
    "evidence_link_id", "evidence_type", "evidence_id", "observed_at", "added_at", "source_status",
}
SOURCE_CONTEXT_KEYS = {"site_id", "scope_id", "device_id"}


def _app(path):
    app = FastAPI()
    register_incident_review_routes(app, lambda: path)
    return app


def _report_endpoint(path):
    route = next(route for route in _app(path).routes
                 if getattr(route, "path", None) == "/incident-reviews/{incident_id}/report.json")
    return route.endpoint


def _link(path, review_id, evidence_type, evidence_id, observed_at="2026-10-01T00:00:00+00:00"):
    with get_connection(path) as connection:
        connection.execute("""INSERT INTO incident_review_evidence
            (incident_id,evidence_type,evidence_id,observed_at,added_at,reason)
            VALUES (?,?,?,?,?,?)""", (review_id, evidence_type, evidence_id, observed_at,
                                           REPORT_AT, "must not appear"))


def _base_review(path, *, title="Case <handoff>", summary="Summary & context", site_id=None):
    return create_review(title=title, summary=summary, site_id=site_id, db_path=path)


def _seed_report_history(path, review_id, *, notes=2, timeline=2):
    with get_connection(path) as connection:
        for index in range(notes):
            connection.execute("""INSERT INTO incident_review_notes
                (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)""",
                (review_id, f"note-{index}", "OPERATOR", f"2026-10-{index + 1:02d}T00:00:00+00:00"))
        for index in range(timeline):
            connection.execute("""INSERT INTO incident_review_events
                (incident_review_id,event_type,actor_source,created_at,field_name,old_value,new_value,
                 evidence_type,evidence_id,summary)
                 VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (review_id, "REVIEW_FIELD_CHANGED", "OPERATOR", f"2026-10-{index + 1:02d}T00:00:00+00:00",
                 "title", "secret-old-value", "secret-new-value", None, None, "Title changed"))


@pytest.fixture
def report_db(tmp_path):
    path = tmp_path / "incident-review-report.db"
    initialize_database(path)
    return path


def test_report_endpoint_contract_headers_filename_snapshot_and_read_only(report_db):
    review = _base_review(report_db)
    _link(report_db, review["id"], "THREAT_DETECTION", 9001)
    _seed_report_history(report_db, review["id"])
    with get_connection(report_db) as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("incident_reviews", "incident_review_evidence", "incident_review_notes",
                          "incident_review_events", "management_audit_events")
        }
        schema_before = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]

    response = _report_endpoint(report_db)(review["id"])
    assert response.status_code == 200
    assert response.media_type == "application/json"
    assert response.headers["cache-control"] == "no-store"
    disposition = response.headers["content-disposition"]
    assert re.fullmatch(
        r'attachment; filename="sentinelip-incident-review-\d+-\d{8}T\d{6}Z\.json"', disposition)
    body = json.loads(response.body)
    assert body["report_schema_version"] == 1
    assert body["generated_at"].endswith("Z")
    assert body["review"]["id"] == review["id"]
    assert "incident_key" in body["review"] and "review_key" not in body["review"]
    assert set(body) == {"report_schema_version", "generated_at", "review", "evidence", "notes", "timeline"}
    assert body["evidence"]["items"][0]["source_status"] == "MISSING"
    assert body["evidence"]["total"] == body["evidence"]["returned"] == 1
    assert body["evidence"]["omitted"] == 0 and body["evidence"]["truncated"] is False
    assert body["notes"]["items"][0]["actor_source"] == "OPERATOR"
    assert "old_value" not in body["timeline"]["items"][0]
    assert "new_value" not in body["timeline"]["items"][0]
    response_text = response.body.decode("utf-8")
    assert "secret-old-value" not in response_text and "secret-new-value" not in response_text
    assert "must not appear" not in response_text
    with get_connection(report_db) as connection:
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before
        }
        schema_after = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    assert after == before
    assert schema_after == schema_before == 46


def test_report_fixed_review_notes_and_timeline_projections(report_db):
    review = _base_review(report_db)
    _seed_report_history(report_db, review["id"])
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    assert set(body["review"]) == set(reports.REVIEW_FIELDS)
    assert body["review"]["incident_key"] == review["incident_key"]
    assert body["review"]["title"] == "Case <handoff>"
    assert body["review"]["summary"] == "Summary & context"
    assert body["review"]["final_summary"] is None
    assert [item["text"] for item in body["notes"]["items"]] == ["note-0", "note-1"]
    assert all(set(item) == {"id", "created_at", "actor_source", "text"} for item in body["notes"]["items"])
    timeline_times = [item["created_at"] for item in body["timeline"]["items"]]
    assert timeline_times[:2] == ["2026-10-01T00:00:00+00:00", "2026-10-02T00:00:00+00:00"]
    assert all(set(item) == {"id", "created_at", "event_type", "actor_source", "field_name",
                             "evidence_type", "evidence_id", "summary"}
               for item in body["timeline"]["items"])
    assert all(item["actor_source"] == "OPERATOR" for item in body["timeline"]["items"])


def test_closed_review_projection_preserves_stored_attribution_summary_and_evidence_bounds(report_db):
    with get_connection(report_db) as connection:
        site_id = connection.execute(
            "INSERT INTO sites(name,description,enabled,created_at,updated_at) VALUES ('Review site','',1,?,?)",
            (REPORT_AT, REPORT_AT),
        ).lastrowid
    review = create_review(title="Closed handoff", summary="Closed case", site_id=site_id,
                           disposition="BENIGN", final_summary="Observed activity was expected.",
                           db_path=report_db)
    update_review(review["id"], {"state": "CLOSED"}, report_db)
    _link(report_db, review["id"], "THREAT_DETECTION", 9010,
          observed_at="2026-10-02T00:00:00+00:00")
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    assert body["review"]["state"] == "CLOSED"
    assert body["review"]["disposition"] == "BENIGN"
    assert body["review"]["site_id"] == site_id
    assert body["review"]["scope_id"] is None and body["review"]["device_id"] is None
    assert body["review"]["final_summary"] == "Observed activity was expected."
    assert body["review"]["closed_at"] is not None
    assert body["review"]["first_evidence_at"] is None
    assert body["review"]["last_evidence_at"] is None
    assert body["evidence"]["items"][0]["observed_at"] == "2026-10-02T00:00:00+00:00"


def test_malformed_optional_timestamps_are_preserved_and_order_deterministically(report_db):
    review = _base_review(report_db)
    with get_connection(report_db) as connection:
        for evidence_id, observed_at in ((1, "not-a-timestamp"), (2, "2026-10-02T00:00:00+00:00")):
            connection.execute("""INSERT INTO incident_review_evidence
                (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,?,?,?,?)""",
                (review["id"], "THREAT_DETECTION", evidence_id, observed_at, REPORT_AT))
        for timestamp in ("not-a-timestamp", "2026-10-02T00:00:00+00:00"):
            connection.execute("INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)",
                               (review["id"], "safe note", "OPERATOR", timestamp))
            connection.execute("INSERT INTO incident_review_events (incident_review_id,event_type,actor_source,created_at) VALUES (?,?,?,?)",
                               (review["id"], "REVIEW_FIELD_CHANGED", "OPERATOR", timestamp))
    first = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    second = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    assert first == second
    assert [item["observed_at"] for item in first["evidence"]["items"]] == [
        "not-a-timestamp", "2026-10-02T00:00:00+00:00",
    ]
    assert {item["created_at"] for item in first["notes"]["items"]} == {
        "not-a-timestamp", "2026-10-02T00:00:00+00:00",
    }


def test_report_missing_review_invalid_id_and_access_boundary(report_db):
    endpoint = _report_endpoint(report_db)
    with pytest.raises(HTTPException) as missing:
        endpoint(999)
    assert missing.value.status_code == 404
    with pytest.raises(HTTPException) as invalid:
        endpoint(0)
    assert invalid.value.status_code == 422
    route = next(route for route in _app(report_db).routes
                 if getattr(route, "path", None) == "/incident-reviews/{incident_id}/report.json")
    from api.remote_sensors import local_management
    assert any(dependency.call is local_management
               for dependency in route.dependant.dependencies)


@pytest.mark.parametrize("evidence_type", [
    "PERIMETER_DETECTION", "PERIMETER_POLICY_CORRELATION", "PERIMETER_HOST_CORRELATION",
    "EXTERNAL_EXPOSURE_CHANGE", "THREAT_DETECTION", "THREAT_CORRELATION", "WEB_DETECTION",
])
def test_all_evidence_types_preserve_missing_references_without_source_payload(report_db, evidence_type):
    review = _base_review(report_db)
    _link(report_db, review["id"], evidence_type, 7000)
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    item = body["evidence"]["items"][0]
    assert item == {
        "evidence_link_id": 1,
        "evidence_type": evidence_type,
        "evidence_id": 7000,
        "observed_at": "2026-10-01T00:00:00+00:00",
        "added_at": REPORT_AT,
        "source_status": "MISSING",
    }


def test_available_source_projection_is_fixed_and_sensitive_source_fields_do_not_leak(report_db):
    review = _base_review(report_db)
    with get_connection(report_db) as connection:
        cursor = connection.execute("""INSERT INTO threat_detections (
            stable_key,threat_type,state,severity,confidence,device_id,source_ip,sensor_id,hostname,
            primary_evidence_type,primary_evidence_id,anchor_id,reason,recommendation,rule_id,rule_version,
            first_seen,last_seen,created_at,updated_at)
            VALUES ('report-threat','SUSPICIOUS_AUTH_ACTIVITY','ANOMALOUS','HIGH','HIGH',NULL,
             '203.0.113.55',NULL,'source.example','SSH_EVENT',1,1,'SECRET_REASON','SECRET_PAYLOAD',
             'safe-rule','1','2026-10-01T00:00:00Z','2026-10-01T00:00:00Z',
             '2026-10-01T00:00:00Z','2026-10-01T00:00:00Z')""")
        threat_id = cursor.lastrowid
    _link(report_db, review["id"], "THREAT_DETECTION", threat_id)
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    item = body["evidence"]["items"][0]
    assert set(item) == BASE_EVIDENCE_KEYS | SOURCE_CONTEXT_KEYS
    assert item["source_status"] == "AVAILABLE"
    assert (item["site_id"], item["scope_id"], item["device_id"]) == (None, None, None)
    serialized = json.dumps(body)
    for forbidden in ("SECRET_REASON", "SECRET_PAYLOAD", "203.0.113.55", "hostname", "source_ip", "recommendation"):
        assert forbidden not in serialized


def _seed_all_report_sources(path):
    site = RemoteSensorStore(path).create_site("Report fixture site")
    network = create_network("10.90.0.0/24", "Report network", "fixture", True, True, path)
    with get_connection(path) as connection:
        scope_id = connection.execute(
            "SELECT scope_id FROM network_scope_links WHERE network_id=?", (network["id"],)
        ).fetchone()[0]
        connection.execute("INSERT INTO remote_scope_sites(scope_id,site_id,created_at) VALUES (?,?,?)",
                           (scope_id, site["id"], REPORT_AT))
    device = create_device("report:private-device", network["id"], None, None, None,
                           REPORT_AT, REPORT_AT, "10.90.0.2", "ONLINE", "HIGH", path)
    public_scope = create_scope(
        scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8", name="Report public scope",
        authorized=True, enabled=True, authorization_confirmed_at=REPORT_AT,
        authorization_confirmation_version="test-v1", authorization_source="test", db_path=path,
    )
    public_device = create_scope_device(public_scope["id"], first_seen=REPORT_AT,
                                        last_seen=REPORT_AT, status="ONLINE", db_path=path)
    with get_connection(path) as connection:
        connection.execute("INSERT INTO remote_scope_sites(scope_id,site_id,created_at) VALUES (?,?,?)",
                           (public_scope["id"], site["id"], REPORT_AT))
        event_id = connection.execute("""INSERT INTO perimeter_events (
            external_event_id,site_id,source_type,source_key,event_type,direction,action,protocol,
            source_ip,destination_ip,observed_at,received_at)
            VALUES ('report-event',?,'OTHER','report-source','OTHER','UNKNOWN','UNKNOWN','OTHER',
                    '203.0.113.1','10.90.0.2',?,?)""",
            (site["id"], REPORT_AT, REPORT_AT)).lastrowid
        perimeter_id = connection.execute("""INSERT INTO perimeter_detections (
            stable_key,detection_type,state,confidence,site_id,primary_event_id,event_ids_json,
            source_ip,destination_ip,protocol,action,event_count,unique_source_count,first_seen,
            last_seen,rule_id,rule_version,reason,created_at)
            VALUES ('report-perimeter','INBOUND_ATTEMPT','REVIEW','HIGH',?,?, '[1]',
                    '203.0.113.1','10.90.0.2','OTHER','UNKNOWN',1,1,?,?, 'rule','1',
                    'SECRET_PERIMETER_REASON',?)""",
            (site["id"], event_id, REPORT_AT, REPORT_AT, REPORT_AT)).lastrowid
        policy_id = connection.execute("""INSERT INTO perimeter_policy_correlations (
            stable_key,correlation_type,state,confidence,site_id,primary_event_id,event_ids_json,
            allowed_event_ids_json,blocked_event_ids_json,source_type,source_key,source_ip,
            destination_ip,protocol,primary_action,event_count,allow_count,blocked_count,
            first_seen,last_seen,rule_id,rule_version,reason,created_at)
            VALUES ('report-policy','BLOCK_THEN_ALLOW','REVIEW','HIGH',?,?, '[1]','[1]','[1]',
                    'OTHER','report-source','203.0.113.1','10.90.0.2','OTHER','ALLOW',2,1,1,
                    ?,?,'rule','1','SECRET_POLICY_REASON',?)""",
            (site["id"], event_id, REPORT_AT, REPORT_AT, REPORT_AT)).lastrowid
        host_id = connection.execute("""INSERT INTO perimeter_host_correlations (
            stable_key,correlation_type,state,confidence,site_id,event_id,scope_id,network_id,
            device_id,destination_ip,protocol,action,observed_at,device_last_seen,device_status,
            identity_confidence,rule_id,rule_version,reason,created_at)
            VALUES ('report-host','DESTINATION_DEVICE_MATCH','REVIEW','HIGH',?,?,?,?,?,'10.90.0.2',
                    'OTHER','UNKNOWN',?,?,'ONLINE','HIGH','rule','1','SECRET_HOST_REASON',?)""",
            (site["id"], event_id, scope_id, network["id"], device["id"], REPORT_AT,
             REPORT_AT, REPORT_AT)).lastrowid
        exposure_id = connection.execute("""INSERT INTO external_exposures (
            stable_key,scope_id,scope_type,canonical_target,device_id,target_ip,port_number,
            transport,service_name,first_seen,last_seen,last_observation_source,last_scanner,
            created_at,updated_at)
            VALUES ('report-exposure',?,'PUBLIC_IPV4','8.8.8.8',?,'8.8.8.8',443,'tcp','https',
                    ?,?,'test','test',?,?)""",
            (public_scope["id"], public_device["id"], REPORT_AT, REPORT_AT, REPORT_AT, REPORT_AT)).lastrowid
        exposure_change_id = connection.execute("""INSERT INTO external_exposure_changes (
            event_key,exposure_id,scope_id,change_type,reason,observed_at,source,scanner,created_at)
            VALUES ('report-change',?,?,'NEW_EXPOSURE','SECRET_CHANGE_REASON',?,'test','test',?)""",
            (exposure_id, public_scope["id"], REPORT_AT, REPORT_AT)).lastrowid
        threat_id = connection.execute("""INSERT INTO threat_detections (
            stable_key,threat_type,state,severity,confidence,device_id,source_ip,hostname,
            primary_evidence_type,primary_evidence_id,anchor_id,reason,recommendation,rule_id,
            rule_version,first_seen,last_seen,created_at,updated_at)
            VALUES ('report-threat-all','SUSPICIOUS_AUTH_ACTIVITY','ANOMALOUS','HIGH','HIGH',?,
                    '203.0.113.2','SECRET_THREAT_HOST','SSH_EVENT',1,1,'SECRET_THREAT_REASON',
                    'SECRET_THREAT_PAYLOAD','rule','1',?,?,?,?)""",
            (device["id"], REPORT_AT, REPORT_AT, REPORT_AT, REPORT_AT)).lastrowid
        correlation_id = connection.execute("""INSERT INTO correlations (
            stable_key,correlation_type,state,severity,confidence,device_id,source_ip,hostname,
            primary_entity_type,primary_entity_id,reason,rule_id,rule_version,first_seen,last_seen,
            created_at,updated_at)
            VALUES ('report-correlation','SSH_AUTH_ACTIVITY_PATTERN','RELATED','MEDIUM','MEDIUM',?,
                    '203.0.113.3','SECRET_CORRELATION_HOST','THREAT',?,'SECRET_CORRELATION_REASON',
                    'rule','1',?,?,?,?)""",
            (device["id"], threat_id, REPORT_AT, REPORT_AT, REPORT_AT, REPORT_AT)).lastrowid
        telemetry_sensor_id = connection.execute("""INSERT INTO telemetry_sensors (
            sensor_key,name,sensor_type,token_salt,token_hash,token_iterations,enabled,privacy_mode,
            retention_days,created_at,updated_at)
            VALUES ('report-web-sensor','Report sensor','BROWSER',x'01','SECRET_SENSOR_TOKEN_HASH',1,
                    1,'MINIMAL',30,?,?)""", (REPORT_AT, REPORT_AT)).lastrowid
        web_id = connection.execute("""INSERT INTO web_detections (
            stable_key,detection_type,severity,confidence,state,sensor_id,device_id,hostname,reason,
            structured_evidence,rule_id,rule_version,first_seen,last_seen,created_at,updated_at)
            VALUES ('report-web','LOGIN_DOMAIN_REVIEW','LOW','MEDIUM','REVIEW',?,?,'SECRET_WEB_HOST',
                    'SECRET_WEB_REASON','SECRET_WEB_PAYLOAD','rule','1',?,?,?,?)""",
            (telemetry_sensor_id, device["id"], REPORT_AT, REPORT_AT, REPORT_AT, REPORT_AT)).lastrowid
    return {
        "PERIMETER_DETECTION": perimeter_id,
        "PERIMETER_POLICY_CORRELATION": policy_id,
        "PERIMETER_HOST_CORRELATION": host_id,
        "EXTERNAL_EXPOSURE_CHANGE": exposure_change_id,
        "THREAT_DETECTION": threat_id,
        "THREAT_CORRELATION": correlation_id,
        "WEB_DETECTION": web_id,
    }


def test_each_supported_source_type_has_the_same_fixed_safe_context_projection(report_db):
    source_ids = _seed_all_report_sources(report_db)
    review = _base_review(report_db)
    for evidence_type, evidence_id in source_ids.items():
        _link(report_db, review["id"], evidence_type, evidence_id)
    report = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    by_type = {item["evidence_type"]: item for item in report["evidence"]["items"]}
    assert set(by_type) == set(reports.SOURCE_QUERIES)
    for evidence_type in reports.SOURCE_QUERIES:
        assert by_type[evidence_type]["source_status"] == "AVAILABLE"
        assert set(by_type[evidence_type]) == BASE_EVIDENCE_KEYS | SOURCE_CONTEXT_KEYS
    assert by_type["PERIMETER_DETECTION"]["site_id"] is not None
    assert by_type["PERIMETER_HOST_CORRELATION"]["scope_id"] is not None
    assert by_type["PERIMETER_HOST_CORRELATION"]["device_id"] is not None
    serialized = json.dumps(report)
    for forbidden in ("SECRET_", "203.0.113.", "8.8.8.8", "target_ip", "source_ip", "structured_evidence"):
        assert forbidden not in serialized


def test_report_collections_select_newest_then_emit_chronologically(report_db):
    review = _base_review(report_db)
    with get_connection(report_db) as connection:
        for index in range(201):
            connection.execute("""INSERT INTO incident_review_evidence
                (incident_id,evidence_type,evidence_id,observed_at,added_at)
                VALUES (?,?,?,?,?)""", (review["id"], "THREAT_DETECTION", index + 1,
                    f"2026-10-{(index % 28) + 1:02d}T00:00:00+00:00", REPORT_AT))
        for index in range(51):
            connection.execute("INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)",
                               (review["id"], f"note-{index}", "OPERATOR", f"2026-10-{(index % 28)+1:02d}T00:00:00+00:00"))
            connection.execute("""INSERT INTO incident_review_events
                (incident_review_id,event_type,actor_source,created_at,summary)
                VALUES (?,?,?,?,?)""", (review["id"], "REVIEW_FIELD_CHANGED", "OPERATOR",
                    f"2026-10-{(index % 28)+1:02d}T00:00:00+00:00", "Fixed summary"))
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    for name, total, returned, omitted in (("evidence", 201, 200, 1), ("notes", 51, 50, 1),
                                            ("timeline", 52, 50, 2)):
        collection = body[name]
        assert (collection["total"], collection["returned"], collection["omitted"], collection["truncated"]) == (
            total, returned, omitted, True)
        assert len(collection["items"]) == returned
    evidence_items = body["evidence"]["items"]
    assert all(item["evidence_id"] != 1 for item in evidence_items)
    assert [(item["observed_at"], item["evidence_id"]) for item in evidence_items] == sorted(
        (item["observed_at"], item["evidence_id"]) for item in evidence_items)
    for name in ("notes", "timeline"):
        rows = body[name]["items"]
        assert [(item["created_at"], item["id"]) for item in rows] == sorted(
            (item["created_at"], item["id"]) for item in rows)


def test_report_collection_envelopes_below_and_exact_caps(report_db):
    review = _base_review(report_db)
    with get_connection(report_db) as connection:
        for index in range(50):
            connection.execute("INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)",
                               (review["id"], str(index), "OPERATOR", f"2026-10-{(index % 28)+1:02d}T00:00:00+00:00"))
        for index in range(49):
            connection.execute("INSERT INTO incident_review_events (incident_review_id,event_type,actor_source,created_at) VALUES (?,?,?,?)",
                               (review["id"], "REVIEW_FIELD_CHANGED", "OPERATOR", f"2026-10-{(index % 28)+1:02d}T00:00:00+00:00"))
        for index in range(200):
            connection.execute("INSERT INTO incident_review_evidence (incident_id,evidence_type,evidence_id,observed_at,added_at) VALUES (?,?,?,?,?)",
                               (review["id"], "WEB_DETECTION", index+1, f"2026-10-{(index % 28)+1:02d}T00:00:00+00:00", REPORT_AT))
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    for name, expected in (("evidence", 200), ("notes", 50), ("timeline", 50)):
        assert body[name]["total"] == body[name]["returned"] == expected
        assert body[name]["omitted"] == 0 and body[name]["truncated"] is False


def test_report_output_ceiling_returns_safe_413(report_db, monkeypatch):
    review = _base_review(report_db, summary="oversize")
    body = reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    monkeypatch.setattr(reports, "MAX_REPORT_JSON_BYTES", 1)
    with pytest.raises(reports.IncidentReviewReportError) as raised:
        reports.serialize_incident_review_report(body)
    assert raised.value.status_code == 413
    with pytest.raises(HTTPException) as raised:
        _report_endpoint(report_db)(review["id"])
    assert raised.value.status_code == 413
    assert raised.value.detail == "Incident review report exceeds the output size limit."


def test_report_uses_one_read_connection_and_bounded_source_query_count(report_db, monkeypatch):
    review = _base_review(report_db)
    for index, evidence_type in enumerate(reports.SOURCE_QUERIES, 1):
        _link(report_db, review["id"], evidence_type, 8000 + index)
    original = reports.get_connection
    calls = []
    traces = []

    def tracked_connection(path):
        calls.append(path)
        connection = original(path)
        connection.set_trace_callback(traces.append)
        return connection

    monkeypatch.setattr(reports, "get_connection", tracked_connection)
    reports.build_incident_review_report(review["id"], REPORT_AT, report_db)
    assert calls == [report_db]
    source_tables = ("perimeter_detections", "perimeter_policy_correlations", "perimeter_host_correlations",
                     "external_exposure_changes", "threat_detections", "correlations", "web_detections")
    for table in source_tables:
        assert sum(re.search(rf"\bFROM\s+{table}\b", statement, re.IGNORECASE) is not None
                   for statement in traces) <= 1
    assert any(statement.strip().upper() == "PRAGMA QUERY_ONLY=ON" for statement in traces)
    assert any(statement.strip().upper() == "BEGIN" for statement in traces)


def test_report_query_plans_use_review_child_indexes(report_db):
    with get_connection(report_db) as connection:
        evidence = connection.execute("EXPLAIN QUERY PLAN SELECT id,evidence_type,evidence_id,observed_at,added_at "
            "FROM incident_review_evidence WHERE incident_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT ?",
            (1, reports.MAX_REPORT_EVIDENCE)).fetchall()
        notes = connection.execute("EXPLAIN QUERY PLAN SELECT id,created_at,actor_source,note_text "
            "FROM incident_review_notes WHERE incident_review_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
            (1, reports.MAX_REPORT_NOTES)).fetchall()
        timeline = connection.execute("EXPLAIN QUERY PLAN SELECT id,created_at,event_type,actor_source,field_name,evidence_type,evidence_id,summary "
            "FROM incident_review_events WHERE incident_review_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
            (1, reports.MAX_REPORT_TIMELINE)).fetchall()
    assert any("idx_incident_review_evidence_time" in row[3] for row in evidence)
    assert any("idx_incident_review_notes_timeline" in row[3] for row in notes)
    assert any("idx_incident_review_events_timeline" in row[3] for row in timeline)
