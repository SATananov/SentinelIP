import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from database.db import initialize_database
from database.telemetry import (
    create_dns_observation,
    create_web_observation,
    get_dns_observation_by_event,
    get_web_observation_by_event,
    list_dns_observations,
    list_sensors,
    list_web_observations,
    provision_sensor,
)
from services.telemetry_models import DnsObservation, WebObservation


OBSERVED_AT = datetime.now(timezone.utc) - timedelta(minutes=1)


def test_telemetry_migrations_are_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"telemetry_sensors", "web_observations", "dns_observations"} <= tables


def test_observation_persistence_and_event_lookup(tmp_path):
    db_path = tmp_path / "test.db"
    sensor, _ = provision_sensor("browser", "Browser", "BROWSER", None, "DOMAIN_ONLY", 30, db_path)
    web = WebObservation("web-1", str(sensor["id"]), OBSERVED_AT, "NAVIGATION", "https://example.test/path?x=1", "DOMAIN_ONLY")
    dns = DnsObservation("dns-1", str(sensor["id"]), OBSERVED_AT, "example.test", "A", "NOERROR", ("192.0.2.10",))
    received_at = datetime.now(timezone.utc)
    retention_until = received_at + timedelta(days=30)
    create_web_observation(
        replace(web, received_at=received_at, retention_until=retention_until),
        db_path,
    )
    create_dns_observation(
        replace(dns, received_at=received_at, retention_until=retention_until),
        db_path,
    )

    assert get_web_observation_by_event(sensor["id"], "web-1", db_path)["path"] is None
    assert get_dns_observation_by_event(sensor["id"], "dns-1", db_path)["queried_domain"] == "example.test"
    assert len(list_web_observations(sensor["id"], db_path)) == 1
    assert len(list_dns_observations(sensor["id"], db_path)) == 1
    assert len(list_sensors(db_path)) == 1