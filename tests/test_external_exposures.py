from datetime import datetime, timedelta

from fastapi.testclient import TestClient

import api.main as api
from database.db import get_connection, initialize_database
from database.inventory import create_scope_device
from database.scopes import create_scope
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from services.service_inventory import ServiceInventoryService
from services.service_models import PortObservation, ServiceDiscoveryResult, ServiceObservation


def _scope_and_device(path):
    scope = create_scope(
        scope_type="PUBLIC_IPV4",
        canonical_target="8.8.8.8",
        name="Synthetic public target",
        description="12A fixture",
        authorized=True,
        enabled=True,
        authorization_confirmed_at="2026-10-13T10:00:00",
        authorization_confirmation_version=PUBLIC_IPV4_CONFIRMATION_VERSION,
        authorization_source="test_explicit_authorization",
        db_path=path,
    )
    device = create_scope_device(
        scope["id"], first_seen="2026-10-13T10:00:00", last_seen="2026-10-13T10:00:00",
        status="ONLINE", db_path=path,
    )
    return scope, device


def _result(at, *, version="9.6", source="12a-test"):
    return ServiceDiscoveryResult(
        target_ip="8.8.8.8",
        scanner="bounded-test-scanner",
        started_at=at,
        completed_at=at,
        ports=(
            PortObservation("8.8.8.8", 22, "tcp", "open", at, source),
            PortObservation("8.8.8.8", 443, "tcp", "open", at, source),
        ),
        services=(
            ServiceObservation(
                "8.8.8.8", 22, "tcp", "ssh", "OpenSSH", version, None,
                "HIGH", at, source,
            ),
        ),
    )


def test_public_service_inventory_projects_normalized_external_exposures(tmp_path):
    path = tmp_path / "external-exposure.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    observed_at = datetime(2026, 10, 13, 10, 15, 0)

    inventory = ServiceInventoryService(path).process_public_result(
        scope, device, _result(observed_at)
    )
    exposures = inventory["external_exposures"]
    assert [(item["port_number"], item["transport"]) for item in exposures] == [(22, "tcp"), (443, "tcp")]
    ssh = exposures[0]
    assert ssh["scope_id"] == scope["id"] and ssh["device_id"] == device["id"]
    assert ssh["scope_type"] == "PUBLIC_IPV4"
    assert ssh["canonical_target"] == "8.8.8.8" and ssh["target_ip"] == "8.8.8.8"
    assert ssh["service_name"] == "ssh" and ssh["product"] == "OpenSSH"
    assert ssh["version"] == "9.6" and ssh["service_confidence"] == "HIGH"
    assert exposures[1]["service_name"] is None and exposures[1]["service_confidence"] is None

    # Exact replay is idempotent at the observation layer.
    ServiceInventoryService(path).process_public_result(scope, device, _result(observed_at))
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM external_exposures").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM external_exposure_observations").fetchone()[0] == 2
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_newer_exposure_observation_updates_latest_fingerprint_without_erasing_history(tmp_path):
    path = tmp_path / "external-exposure-update.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    first = datetime(2026, 10, 13, 10, 15, 0)
    second = first + timedelta(minutes=10)
    service = ServiceInventoryService(path)
    service.process_public_result(scope, device, _result(first, version="9.6"))
    updated = service.process_public_result(scope, device, _result(second, version="9.7"))

    ssh = updated["external_exposures"][0]
    assert ssh["version"] == "9.7"
    assert ssh["first_seen"] == first.isoformat(timespec="seconds")
    assert ssh["last_seen"] == second.isoformat(timespec="seconds")
    with get_connection(path) as connection:
        rows = connection.execute(
            "SELECT version FROM external_exposure_observations WHERE port_number=22 ORDER BY observed_at"
        ).fetchall()
    assert rows == [("9.6",), ("9.7",)]


def test_external_exposure_read_api_is_bounded_and_read_only(monkeypatch, tmp_path):
    path = tmp_path / "external-exposure-api.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    at = datetime(2026, 10, 13, 10, 15, 0)
    ServiceInventoryService(path).process_public_result(scope, device, _result(at))
    monkeypatch.setattr(api, "DB_PATH", path)
    client = TestClient(api.app)

    listing = client.get(f"/external-exposures?scope_id={scope['id']}&port_number=22")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1 and body["count"] == 1
    exposure = body["items"][0]
    assert client.get(f"/external-exposures/{exposure['id']}").json() == exposure
    observations = client.get(f"/external-exposures/{exposure['id']}/observations").json()
    assert observations["total"] == 1 and observations["items"][0]["scanner"] == "bounded-test-scanner"
    assert client.get("/external-exposures?target_ip=192.168.1.1").status_code == 422
    assert client.get("/external-exposures/999999").status_code == 404
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/external-exposures"].keys()) == {"get"}


def test_migration_37_is_additive_idempotent_and_fk_clean(tmp_path, monkeypatch):
    import database.migrations as migrations

    path = tmp_path / "migration-37.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:36])
    initialize_database(path)
    scope, device = _scope_and_device(path)
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 37
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"external_exposures", "external_exposure_observations"} <= tables
        assert connection.execute("SELECT id FROM devices WHERE id=?", (device["id"],)).fetchone()
        assert connection.execute("SELECT id FROM authorized_scopes WHERE id=?", (scope["id"],)).fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
