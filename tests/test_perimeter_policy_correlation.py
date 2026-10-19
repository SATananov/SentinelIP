import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import api.main as api_main
from database.db import get_connection, initialize_database
from database.perimeter import persist_perimeter_event
from database.perimeter_policy_correlations import (
    get_perimeter_policy_correlation,
    query_perimeter_policy_correlations,
)
from database.remote_sensors import RemoteSensorStore
from services.perimeter_models import PerimeterEvent
from local_operator_client import make_local_test_client
from services.perimeter_policy_engine import PerimeterPolicyCorrelationEngine

AT = datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc)


def make_event(site_id, number=1, **changes):
    values = dict(
        external_event_id=f"policy-{number:04d}", site_id=site_id, sensor_id=None,
        source_type="FIREWALL", source_key="edge-fw", observed_at=AT + timedelta(seconds=number),
        event_type="POLICY_DECISION", direction="INBOUND", action="BLOCK", protocol="TCP",
        source_ip="203.0.113.40", destination_ip="192.168.1.20",
        source_port=51000 + number, destination_port=22, interface="wan0",
        source_reference="rule:wan", raw_event_hash=f"{1000 + number:064x}", metadata=None,
    )
    values.update(changes)
    return PerimeterEvent(**values)


def setup_site(path, name="Policy correlation site"):
    return RemoteSensorStore(path).create_site(name)


def persist_and_correlate(path, event):
    row = persist_perimeter_event(event, path)
    correlation = PerimeterPolicyCorrelationEngine(path).evaluate_event(row["id"])
    return row, correlation


def test_block_then_allow_creates_review_correlation(tmp_path):
    path = tmp_path / "policy.db"
    site = setup_site(path)
    blocked, first = persist_and_correlate(path, make_event(site["id"], 1, action="BLOCK"))
    allowed, correlation = persist_and_correlate(path, make_event(site["id"], 2, action="ALLOW"))
    assert first is None
    assert correlation["correlation_type"] == "BLOCK_THEN_ALLOW"
    assert correlation["state"] == "REVIEW" and correlation["confidence"] == "HIGH"
    assert correlation["event_ids"] == [blocked["id"], allowed["id"]]
    assert correlation["allowed_event_ids"] == [allowed["id"]]
    assert correlation["blocked_event_ids"] == [blocked["id"]]
    assert correlation["allow_count"] == 1 and correlation["blocked_count"] == 1
    assert "does not establish intrusion or compromise" in correlation["reason"]


def test_allow_then_reject_creates_review_correlation(tmp_path):
    path = tmp_path / "policy.db"
    site = setup_site(path)
    allowed, first = persist_and_correlate(path, make_event(site["id"], 1, action="ALLOW"))
    rejected, correlation = persist_and_correlate(path, make_event(site["id"], 2, action="REJECT"))
    assert first is None
    assert correlation["correlation_type"] == "ALLOW_THEN_BLOCK"
    assert correlation["primary_action"] == "REJECT"
    assert correlation["event_ids"] == [allowed["id"], rejected["id"]]


def test_same_policy_and_unknown_do_not_correlate(tmp_path):
    path = tmp_path / "policy.db"
    site = setup_site(path)
    for number, action in ((1, "BLOCK"), (2, "REJECT"), (3, "UNKNOWN")):
        _, correlation = persist_and_correlate(path, make_event(site["id"], number, action=action))
        assert correlation is None
    assert query_perimeter_policy_correlations(db_path=path)["total"] == 0


def test_correlation_does_not_mix_flow_identity_or_site(tmp_path):
    path = tmp_path / "policy.db"
    first_site = setup_site(path)
    second_site = setup_site(path, "Other policy site")
    persist_and_correlate(path, make_event(first_site["id"], 1, action="BLOCK"))
    variants = (
        make_event(first_site["id"], 2, action="ALLOW", destination_port=443),
        make_event(first_site["id"], 3, action="ALLOW", source_ip="203.0.113.41"),
        make_event(first_site["id"], 4, action="ALLOW", source_key="other-fw"),
        make_event(second_site["id"], 5, action="ALLOW"),
        make_event(first_site["id"], 6, action="ALLOW", direction="OUTBOUND"),
    )
    for event in variants:
        _, correlation = persist_and_correlate(path, event)
        assert correlation is None


def test_five_minute_boundary_is_inclusive_but_older_evidence_is_not(tmp_path):
    path = tmp_path / "policy.db"
    site = setup_site(path)
    first = make_event(site["id"], 1, action="BLOCK", observed_at=AT)
    persist_and_correlate(path, first)
    _, at_boundary = persist_and_correlate(
        path, make_event(site["id"], 2, action="ALLOW", observed_at=AT + timedelta(minutes=5))
    )
    assert at_boundary is not None and at_boundary["correlation_type"] == "BLOCK_THEN_ALLOW"

    path2 = tmp_path / "policy2.db"
    site2 = setup_site(path2)
    persist_and_correlate(path2, make_event(site2["id"], 1, action="BLOCK", observed_at=AT))
    _, too_late = persist_and_correlate(
        path2, make_event(site2["id"], 2, action="ALLOW", observed_at=AT + timedelta(minutes=5, seconds=1))
    )
    assert too_late is None


def test_repeated_evaluation_is_idempotent(tmp_path):
    path = tmp_path / "policy.db"
    site = setup_site(path)
    persist_and_correlate(path, make_event(site["id"], 1, action="BLOCK"))
    primary = persist_perimeter_event(make_event(site["id"], 2, action="ALLOW"), path)
    engine = PerimeterPolicyCorrelationEngine(path)
    first = engine.evaluate_event(primary["id"])
    second = engine.evaluate_event(primary["id"])
    assert first["id"] == second["id"]
    assert first["idempotent"] is False and second["idempotent"] is True


def test_history_accumulates_bounded_matching_policy_evidence(tmp_path):
    path = tmp_path / "policy.db"
    site = setup_site(path)
    persist_and_correlate(path, make_event(site["id"], 1, action="BLOCK"))
    _, second = persist_and_correlate(path, make_event(site["id"], 2, action="ALLOW"))
    _, third = persist_and_correlate(path, make_event(site["id"], 3, action="BLOCK"))
    assert second["correlation_type"] == "BLOCK_THEN_ALLOW"
    assert third["correlation_type"] == "ALLOW_THEN_BLOCK"
    assert third["event_count"] == 3
    assert third["allow_count"] == 1 and third["blocked_count"] == 2


def test_read_api_is_bounded_and_read_only(tmp_path, monkeypatch):
    path = tmp_path / "api.db"
    site = setup_site(path)
    persist_and_correlate(path, make_event(site["id"], 1, action="BLOCK"))
    _, correlation = persist_and_correlate(path, make_event(site["id"], 2, action="ALLOW"))
    monkeypatch.setattr(api_main, "DB_PATH", path)
    client = make_local_test_client(api_main.app)
    response = client.get(
        f"/perimeter-policy-correlations?site_id={site['id']}&correlation_type=BLOCK_THEN_ALLOW"
        "&source_type=FIREWALL&source_key=edge-fw&destination_port=22"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1 and body["correlations"][0]["id"] == correlation["id"]
    assert body["correlations"][0]["source_key"] == "edge-fw"
    detail = client.get(f"/perimeter-policy-correlations/{correlation['id']}")
    assert detail.status_code == 200 and detail.json()["state"] == "REVIEW"
    assert client.post("/perimeter-policy-correlations", json={}).status_code == 405


def test_migration_35_preserves_11c_data_and_is_fk_clean(tmp_path, monkeypatch):
    import database.migrations as migrations
    from tests.historical_migration_helpers import insert_site
    path = tmp_path / "upgrade.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:34])
    initialize_database(path)
    with get_connection(path) as connection:
        site = insert_site(connection, "Policy correlation site")
    event = persist_perimeter_event(make_event(site["id"], 1), path)
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 45
        assert connection.execute("SELECT id FROM perimeter_events WHERE id=?", (event["id"],)).fetchone()
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='perimeter_policy_correlations'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_missing_event_cannot_be_correlated(tmp_path):
    path = tmp_path / "missing.db"
    initialize_database(path)
    with pytest.raises(LookupError):
        PerimeterPolicyCorrelationEngine(path).evaluate_event(999)
