import sqlite3
from dataclasses import replace
from datetime import datetime, timezone

import pytest

import api.main as api_main
from database.db import get_connection, initialize_database
from database.perimeter import get_perimeter_event, persist_perimeter_event, query_perimeter_events
from database.remote_sensors import RemoteSensorStore
from services.perimeter_models import PerimeterEvent, PerimeterModelError
from local_operator_client import make_local_test_client


AT = datetime(2026, 10, 13, 4, 0, tzinfo=timezone.utc)


def site(path):
    return RemoteSensorStore(path).create_site("Perimeter test site")


def event(site_id, **changes):
    values = dict(
        external_event_id="fw-0001",
        site_id=site_id,
        source_type="FIREWALL",
        source_key="edge-fw-1",
        observed_at=AT,
        event_type="CONNECTION_ATTEMPT",
        direction="INBOUND",
        action="BLOCK",
        protocol="TCP",
        source_ip="203.0.113.9",
        destination_ip="198.51.100.10",
        source_port=49822,
        destination_port=22,
        interface="wan0",
        source_reference="syslog:edge-fw-1",
        raw_event_hash="a" * 64,
        metadata={"rule": "deny-wan-ssh"},
    )
    values.update(changes)
    return PerimeterEvent(**values)


def test_model_normalizes_factual_fields_and_rejects_claims_or_secrets():
    item = event(1)
    assert item.source_type.value == "FIREWALL"
    assert item.direction.value == "INBOUND"
    assert item.action.value == "BLOCK"
    assert item.protocol.value == "TCP"
    assert item.observed_at.tzinfo is not None

    with pytest.raises(PerimeterModelError, match="destination_port"):
        event(1, destination_port=None)
    with pytest.raises(PerimeterModelError, match="ICMP"):
        event(1, protocol="ICMP", destination_port=8)
    with pytest.raises(PerimeterModelError, match="canonical"):
        event(1, source_ip="2001:0db8::1")
    with pytest.raises(PerimeterModelError, match="Sensitive"):
        event(1, metadata={"token": "do-not-store"})
    with pytest.raises(PerimeterModelError, match="SHA-256"):
        event(1, raw_event_hash="not-a-digest")


def test_persistence_is_idempotent_but_conflicting_reuse_is_rejected(tmp_path):
    path = tmp_path / "perimeter.db"
    current_site = site(path)
    candidate = event(current_site["id"])
    first = persist_perimeter_event(candidate, path)
    second = persist_perimeter_event(candidate, path)
    assert first["id"] == second["id"]
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    assert second["metadata"] == {"rule": "deny-wan-ssh"}

    with pytest.raises(sqlite3.IntegrityError, match="identity conflicts"):
        persist_perimeter_event(replace(candidate, action="ALLOW"), path)


def test_query_filters_and_order_are_bounded(tmp_path):
    path = tmp_path / "perimeter.db"
    current_site = site(path)
    first = persist_perimeter_event(event(current_site["id"]), path)
    persist_perimeter_event(
        event(
            current_site["id"],
            external_event_id="fw-0002",
            action="ALLOW",
            source_ip="203.0.113.10",
            destination_port=443,
        ),
        path,
    )
    result = query_perimeter_events(site_id=current_site["id"], action="BLOCK", limit=1, offset=0, db_path=path)
    assert result["total"] == 1
    assert [row["id"] for row in result["items"]] == [first["id"]]
    assert get_perimeter_event(first["id"], path)["source_ip"] == "203.0.113.9"


def test_sensor_must_belong_to_same_site(tmp_path):
    path = tmp_path / "perimeter.db"
    store = RemoteSensorStore(path)
    a = store.create_site("A")
    b = store.create_site("B")
    invite = store.create_enrollment(b["id"])
    sensor = store.consume_enrollment(invite.secret, name="sensor-b", platform="linux", version="1")
    with pytest.raises(sqlite3.IntegrityError):
        persist_perimeter_event(event(a["id"], sensor_id=sensor.record["id"]), path)


def test_migration_33_is_additive_idempotent_and_fk_clean(tmp_path, monkeypatch):
    import database.migrations as migrations
    from tests.historical_migration_helpers import insert_site

    path = tmp_path / "upgrade.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:32])
    initialize_database(path)
    with get_connection(path) as connection:
        existing_site = insert_site(connection, "Existing")
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='perimeter_events'").fetchone()
        assert connection.execute("SELECT name FROM sites WHERE id=?", (existing_site["id"],)).fetchone()[0] == "Existing"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_api_is_read_only_and_supports_review_filters(tmp_path, monkeypatch):
    path = tmp_path / "api.db"
    current_site = site(path)
    stored = persist_perimeter_event(event(current_site["id"]), path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    client = make_local_test_client(api_main.app)

    listing = client.get(f"/perimeter-events?site_id={current_site['id']}&direction=INBOUND&action=BLOCK")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1 and body["events"][0]["id"] == stored["id"]
    assert body["filters"]["action"] == "BLOCK"

    detail = client.get(f"/perimeter-events/{stored['id']}")
    assert detail.status_code == 200 and detail.json()["external_event_id"] == "fw-0001"
    assert client.get("/perimeter-events/999999").status_code == 404
    assert client.post("/perimeter-events", json={}).status_code == 405
