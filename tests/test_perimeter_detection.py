import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from database.db import get_connection, initialize_database
from database.perimeter import persist_perimeter_event
from database.perimeter_detections import get_perimeter_detection, query_perimeter_detections
from database.remote_sensors import RemoteSensorStore
from services.perimeter_detection_engine import PerimeterDetectionEngine
from services.perimeter_models import PerimeterEvent

AT = datetime(2026, 10, 13, 5, 0, tzinfo=timezone.utc)


def make_event(site_id, number=1, **changes):
    values = dict(
        external_event_id=f"fw-{number:04d}", site_id=site_id, sensor_id=None,
        source_type="FIREWALL", source_key="edge-fw", observed_at=AT + timedelta(seconds=number),
        event_type="POLICY_DECISION", direction="INBOUND", action="BLOCK", protocol="TCP",
        source_ip="203.0.113.20", destination_ip="192.168.1.10",
        source_port=50000 + number, destination_port=22, interface="wan0",
        source_reference="rule:wan", raw_event_hash=f"{number:064x}", metadata=None,
    )
    values.update(changes)
    return PerimeterEvent(**values)


def setup_site(path):
    return RemoteSensorStore(path).create_site("Perimeter detection site")


def persist_and_eval(path, candidate):
    row = persist_perimeter_event(candidate, path)
    detection = PerimeterDetectionEngine(path).evaluate_event(row["id"])
    return row, detection


def test_single_inbound_policy_decision_becomes_review_signal(tmp_path):
    path = tmp_path / "detect.db"
    site = setup_site(path)
    event, detection = persist_and_eval(path, make_event(site["id"]))
    assert detection["detection_type"] == "INBOUND_ATTEMPT"
    assert detection["state"] == "REVIEW" and detection["confidence"] == "HIGH"
    assert detection["event_ids"] == [event["id"]]
    assert detection["action"] == "BLOCK"
    assert "attack" in detection["reason"].lower() and "does not" in detection["reason"].lower()


def test_outbound_flow_and_other_evidence_do_not_create_attempt_detection(tmp_path):
    path = tmp_path / "detect.db"
    site = setup_site(path)
    for index, changes in enumerate((
        {"direction": "OUTBOUND"}, {"event_type": "FLOW"}, {"event_type": "OTHER"}
    ), start=1):
        row = persist_perimeter_event(make_event(site["id"], index, **changes), path)
        assert PerimeterDetectionEngine(path).evaluate_event(row["id"]) is None
    assert query_perimeter_detections(db_path=path)["total"] == 0


def test_fifth_matching_event_is_repeated_attempt_signal(tmp_path):
    path = tmp_path / "detect.db"
    site = setup_site(path)
    detections = []
    for index in range(1, 6):
        _, detection = persist_and_eval(path, make_event(site["id"], index))
        detections.append(detection)
    assert [row["detection_type"] for row in detections[:4]] == ["INBOUND_ATTEMPT"] * 4
    repeated = detections[-1]
    assert repeated["detection_type"] == "REPEATED_INBOUND_ATTEMPTS"
    assert repeated["event_count"] == 5 and len(repeated["event_ids"]) == 5
    assert repeated["source_ip"] == "203.0.113.20" and repeated["destination_port"] == 22


def test_rule_does_not_mix_action_port_source_or_site(tmp_path):
    path = tmp_path / "detect.db"
    first_site = setup_site(path)
    second_site = RemoteSensorStore(path).create_site("Other")
    for index in range(1, 5):
        persist_and_eval(path, make_event(first_site["id"], index))
    variants = (
        make_event(first_site["id"], 5, action="ALLOW"),
        make_event(first_site["id"], 6, destination_port=443),
        make_event(first_site["id"], 7, source_ip="203.0.113.21"),
        make_event(second_site["id"], 8),
    )
    for candidate in variants:
        _, detection = persist_and_eval(path, candidate)
        assert detection["detection_type"] == "INBOUND_ATTEMPT"
        assert detection["event_count"] == 1


def test_five_minute_boundary_is_inclusive_and_older_event_is_excluded(tmp_path):
    path = tmp_path / "detect.db"
    site = setup_site(path)
    times = [AT, AT + timedelta(minutes=4, seconds=57), AT + timedelta(minutes=4, seconds=58),
             AT + timedelta(minutes=4, seconds=59), AT + timedelta(minutes=5)]
    for index, when in enumerate(times, start=1):
        candidate = make_event(site["id"], index, observed_at=when)
        _, detection = persist_and_eval(path, candidate)
    assert detection["detection_type"] == "REPEATED_INBOUND_ATTEMPTS"
    sixth = make_event(site["id"], 6, observed_at=AT + timedelta(minutes=5, seconds=1))
    _, later = persist_and_eval(path, sixth)
    assert later["detection_type"] == "INBOUND_ATTEMPT" or later["event_count"] < 6
    assert 1 not in later["event_ids"]


def test_detection_persistence_is_idempotent_for_same_evidence(tmp_path):
    path = tmp_path / "detect.db"
    site = setup_site(path)
    event = persist_perimeter_event(make_event(site["id"]), path)
    engine = PerimeterDetectionEngine(path)
    first = engine.evaluate_event(event["id"])
    second = engine.evaluate_event(event["id"])
    assert first["id"] == second["id"]
    assert first["idempotent"] is False and second["idempotent"] is True


def test_read_api_is_bounded_and_read_only(tmp_path, monkeypatch):
    path = tmp_path / "api.db"
    site = setup_site(path)
    _, detection = persist_and_eval(path, make_event(site["id"]))
    monkeypatch.setattr(api_main, "DB_PATH", path)
    client = TestClient(api_main.app)
    response = client.get(f"/perimeter-detections?site_id={site['id']}&action=BLOCK&destination_port=22")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1 and body["detections"][0]["id"] == detection["id"]
    detail = client.get(f"/perimeter-detections/{detection['id']}")
    assert detail.status_code == 200 and detail.json()["state"] == "REVIEW"
    assert client.post("/perimeter-detections", json={}).status_code == 405


def test_migration_34_preserves_perimeter_events_and_is_fk_clean(tmp_path, monkeypatch):
    import database.migrations as migrations
    path = tmp_path / "upgrade.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:33])
    initialize_database(path)
    site = setup_site(path)
    existing = persist_perimeter_event(make_event(site["id"]), path)
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 43
        assert connection.execute("SELECT id FROM perimeter_events WHERE id=?", (existing["id"],)).fetchone()
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='perimeter_detections'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_missing_event_cannot_be_evaluated(tmp_path):
    path = tmp_path / "missing.db"
    initialize_database(path)
    with pytest.raises(LookupError):
        PerimeterDetectionEngine(path).evaluate_event(999)
