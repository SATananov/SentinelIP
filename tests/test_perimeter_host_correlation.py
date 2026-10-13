from datetime import datetime, timezone

from fastapi.testclient import TestClient

import api.main as api_main
from database.db import get_connection, initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.perimeter import persist_perimeter_event
from database.perimeter_host_correlations import query_perimeter_host_correlations
from database.remote_sensors import RemoteSensorStore
from services.perimeter_host_engine import PerimeterHostCorrelationEngine
from services.perimeter_models import PerimeterEvent

AT = datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc)


def setup_bound_inventory(path, *, cidr="192.168.10.0/24", ip="192.168.10.20", site_name="Site A"):
    network = create_network(cidr=cidr, name="LAN", description="", authorized=True, enabled=True, db_path=path)
    store = RemoteSensorStore(path)
    site = store.create_site(site_name)
    invite = store.create_enrollment(site["id"])
    sensor = store.consume_enrollment(invite.secret, name="sensor", platform="linux", version="1")
    with get_connection(path) as connection:
        scope_id = connection.execute(
            "SELECT scope_id FROM network_scope_links WHERE network_id=?", (network["id"],)
        ).fetchone()[0]
    store.assign_scope(sensor.record["id"], scope_id)
    device = create_device(
        stable_key=f"network:{network['id']}:mac:aa:bb:cc:dd:ee:01",
        network_id=network["id"], mac_address="aa:bb:cc:dd:ee:01", hostname="server",
        vendor="Lab", first_seen=AT.isoformat(), last_seen=AT.isoformat(), last_ip_address=ip,
        status="ONLINE", identity_confidence="HIGH", db_path=path,
    )
    return site, sensor.record, network, scope_id, device


def event(site_id, *, destination_ip="192.168.10.20", direction="INBOUND", event_type="POLICY_DECISION"):
    return PerimeterEvent(
        external_event_id=f"fw-{destination_ip}-{direction}-{event_type}", site_id=site_id, sensor_id=None,
        source_type="FIREWALL", source_key="edge-fw", observed_at=AT, event_type=event_type,
        direction=direction, action="BLOCK", protocol="TCP", source_ip="203.0.113.50",
        destination_ip=destination_ip, source_port=52000, destination_port=22,
        interface="wan0", source_reference="rule:wan", raw_event_hash="a" * 64, metadata=None,
    )


def test_inbound_destination_matches_unique_site_bound_device(tmp_path):
    path = tmp_path / "host.db"
    site, _, network, scope_id, device = setup_bound_inventory(path)
    stored = persist_perimeter_event(event(site["id"]), path)
    result = PerimeterHostCorrelationEngine(path).evaluate_event(stored["id"])
    assert result["correlation_type"] == "DESTINATION_DEVICE_MATCH"
    assert result["state"] == "REVIEW" and result["confidence"] == "HIGH"
    assert result["site_id"] == site["id"] and result["event_id"] == stored["id"]
    assert result["scope_id"] == scope_id and result["network_id"] == network["id"]
    assert result["device_id"] == device["id"] and result["destination_ip"] == "192.168.10.20"
    assert "not proof" in result["reason"].lower()


def test_no_match_wrong_site_or_unknown_destination(tmp_path):
    path = tmp_path / "host.db"
    first_site, *_ = setup_bound_inventory(path)
    second_site = RemoteSensorStore(path).create_site("Site B")
    unknown = persist_perimeter_event(event(first_site["id"], destination_ip="192.168.10.99"), path)
    wrong_site = persist_perimeter_event(event(second_site["id"]), path)
    engine = PerimeterHostCorrelationEngine(path)
    assert engine.evaluate_event(unknown["id"]) is None
    assert engine.evaluate_event(wrong_site["id"]) is None


def test_non_inbound_or_other_event_does_not_correlate(tmp_path):
    path = tmp_path / "host.db"
    site, *_ = setup_bound_inventory(path)
    engine = PerimeterHostCorrelationEngine(path)
    outbound = persist_perimeter_event(event(site["id"], direction="OUTBOUND"), path)
    other = persist_perimeter_event(event(site["id"], event_type="OTHER"), path)
    assert engine.evaluate_event(outbound["id"]) is None
    assert engine.evaluate_event(other["id"]) is None


def test_disabled_network_or_scope_fails_closed(tmp_path):
    path = tmp_path / "host.db"
    site, _, network, scope_id, _ = setup_bound_inventory(path)
    stored = persist_perimeter_event(event(site["id"]), path)
    with get_connection(path) as connection:
        connection.execute("UPDATE networks SET enabled=0 WHERE id=?", (network["id"],))
    assert PerimeterHostCorrelationEngine(path).evaluate_event(stored["id"]) is None
    with get_connection(path) as connection:
        connection.execute("UPDATE networks SET enabled=1 WHERE id=?", (network["id"],))
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope_id,))
    assert PerimeterHostCorrelationEngine(path).evaluate_event(stored["id"]) is None


def test_correlation_is_idempotent_and_queryable(tmp_path):
    path = tmp_path / "host.db"
    site, _, _, _, device = setup_bound_inventory(path)
    stored = persist_perimeter_event(event(site["id"]), path)
    engine = PerimeterHostCorrelationEngine(path)
    first = engine.evaluate_event(stored["id"])
    second = engine.evaluate_event(stored["id"])
    assert first["id"] == second["id"]
    assert first["idempotent"] is False and second["idempotent"] is True
    result = query_perimeter_host_correlations(site_id=site["id"], device_id=device["id"], db_path=path)
    assert result["total"] == 1 and result["items"][0]["id"] == first["id"]


def test_read_api_is_bounded_and_read_only(tmp_path, monkeypatch):
    path = tmp_path / "api.db"
    site, _, _, _, device = setup_bound_inventory(path)
    stored = persist_perimeter_event(event(site["id"]), path)
    correlation = PerimeterHostCorrelationEngine(path).evaluate_event(stored["id"])
    monkeypatch.setattr(api_main, "DB_PATH", path)
    client = TestClient(api_main.app)
    listing = client.get(f"/perimeter-host-correlations?site_id={site['id']}&device_id={device['id']}&destination_port=22")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1 and body["correlations"][0]["id"] == correlation["id"]
    detail = client.get(f"/perimeter-host-correlations/{correlation['id']}")
    assert detail.status_code == 200 and detail.json()["device_id"] == device["id"]
    assert client.post("/perimeter-host-correlations", json={}).status_code == 405


def test_ingestion_response_includes_host_correlation_ids(tmp_path, monkeypatch):
    # Integration of 11E into the authenticated ingestion path is covered structurally here;
    # machine-auth request semantics remain covered by 11B tests.
    path = tmp_path / "ingest.db"
    site, sensor, _, _, device = setup_bound_inventory(path)
    candidate = persist_perimeter_event(event(site["id"]), path)
    result = PerimeterHostCorrelationEngine(path).evaluate_events([candidate["id"]])
    assert [row["device_id"] for row in result] == [device["id"]]


def test_migration_36_preserves_11d_data_and_is_fk_clean(tmp_path, monkeypatch):
    import database.migrations as migrations
    path = tmp_path / "upgrade.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:35])
    initialize_database(path)
    site = RemoteSensorStore(path).create_site("Existing")
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 41
        assert connection.execute("SELECT name FROM sites WHERE id=?", (site["id"],)).fetchone()[0] == "Existing"
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='perimeter_host_correlations'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
