from datetime import datetime, timedelta


import api.main as api
from database import external_exposure_changes as change_db
from database.db import get_connection, initialize_database
from database.inventory import create_scope_device
from database.scopes import create_scope
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from services.service_inventory import ServiceInventoryService
from local_operator_client import make_local_test_client
from services.service_models import PortObservation, ServiceDiscoveryResult, ServiceObservation


def _scope_device(path):
    scope = create_scope(
        scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8", name="12D target", description="fixture",
        authorized=True, enabled=True, authorization_confirmed_at="2026-10-13T13:00:00",
        authorization_confirmation_version=PUBLIC_IPV4_CONFIRMATION_VERSION,
        authorization_source="test_explicit_authorization", db_path=path,
    )
    device = create_scope_device(
        scope["id"], first_seen="2026-10-13T13:00:00", last_seen="2026-10-13T13:00:00",
        status="ONLINE", db_path=path,
    )
    return scope, device


def _result(at, *, port=443, service_name="https", product="nginx", version="1.0", open_port=True):
    ports = ()
    services = ()
    if open_port:
        ports = (PortObservation("8.8.8.8", port, "tcp", "open", at, "12d-test"),)
        if service_name is not None or product is not None or version is not None:
            services = (ServiceObservation(
                "8.8.8.8", port, "tcp", service_name, product, version, None,
                "HIGH", at, "12d-test",
            ),)
    return ServiceDiscoveryResult(
        target_ip="8.8.8.8", scanner="bounded-test-scanner",
        started_at=at, completed_at=at, ports=ports, services=services,
    )


def test_change_detection_tracks_new_fingerprint_disappear_and_reappear_idempotently(tmp_path):
    path = tmp_path / "changes.db"
    initialize_database(path)
    scope, device = _scope_device(path)
    service = ServiceInventoryService(path)
    first = datetime(2026, 10, 13, 13, 10, 0)

    service.process_public_result(scope, device, _result(first))
    # Exact replay cannot create another change.
    service.process_public_result(scope, device, _result(first))
    second = first + timedelta(minutes=10)
    service.process_public_result(scope, device, _result(second, version="1.1"))
    third = second + timedelta(minutes=10)
    service.process_public_result(scope, device, _result(third, open_port=False))
    fourth = third + timedelta(minutes=10)
    service.process_public_result(scope, device, _result(fourth, version="1.1"))

    result = change_db.query_changes(scope_id=scope["id"], db_path=path)
    kinds = [item["change_type"] for item in reversed(result["items"])]
    assert kinds == [
        "NEW_EXPOSURE", "FINGERPRINT_CHANGED",
        "EXPOSURE_DISAPPEARED", "EXPOSURE_REAPPEARED",
    ]
    presence = change_db.get_presence(result["items"][0]["exposure_id"], path)
    assert presence["presence_state"] == "PRESENT"
    assert presence["last_absent_at"] == third.isoformat(timespec="seconds")
    assert presence["last_present_at"] == fourth.isoformat(timespec="seconds")


def test_service_identity_change_is_separate_from_vulnerability_claims(tmp_path):
    path = tmp_path / "service-change.db"
    initialize_database(path)
    scope, device = _scope_device(path)
    service = ServiceInventoryService(path)
    first = datetime(2026, 10, 13, 13, 10, 0)
    service.process_public_result(scope, device, _result(first, service_name="https", product="nginx"))
    service.process_public_result(
        scope, device,
        _result(first + timedelta(minutes=5), service_name="http-proxy", product="proxy"),
    )
    result = change_db.query_changes(change_type="SERVICE_CHANGED", db_path=path)
    assert result["total"] == 1
    item = result["items"][0]
    assert item["previous_value"] == "https"
    assert item["current_value"] == "http-proxy"
    assert "vulnerab" not in item["reason"].lower()
    assert "comprom" not in item["reason"].lower()


def test_older_completed_scan_cannot_mark_newer_exposure_absent(tmp_path):
    path = tmp_path / "out-of-order.db"
    initialize_database(path)
    scope, device = _scope_device(path)
    service = ServiceInventoryService(path)
    newer = datetime(2026, 10, 13, 14, 0, 0)
    service.process_public_result(scope, device, _result(newer))
    service.process_public_result(scope, device, _result(newer - timedelta(minutes=20), open_port=False))
    changes = change_db.query_changes(change_type="EXPOSURE_DISAPPEARED", db_path=path)
    assert changes["total"] == 0
    exposure_id = change_db.query_changes(change_type="NEW_EXPOSURE", db_path=path)["items"][0]["exposure_id"]
    assert change_db.get_presence(exposure_id, path)["presence_state"] == "PRESENT"


def test_change_api_is_read_only_bounded_and_filterable(monkeypatch, tmp_path):
    path = tmp_path / "changes-api.db"
    initialize_database(path)
    scope, device = _scope_device(path)
    at = datetime(2026, 10, 13, 13, 10, 0)
    ServiceInventoryService(path).process_public_result(scope, device, _result(at))
    monkeypatch.setattr(api, "DB_PATH", path)
    client = make_local_test_client(api.app)

    response = client.get(
        f"/external-exposure-changes?scope_id={scope['id']}&change_type=NEW_EXPOSURE&presence_state=PRESENT"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1 and body["count"] == 1
    change_id = body["items"][0]["id"]
    assert client.get(f"/external-exposure-changes/{change_id}").status_code == 200
    assert client.get("/external-exposure-changes?target_ip=192.168.1.1").status_code == 422
    assert client.get("/external-exposure-changes/999999").status_code == 404
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/external-exposure-changes"].keys()) == {"get"}
    assert set(paths["/external-exposure-changes/{change_id}"].keys()) == {"get"}


def test_migration_40_backfills_presence_without_inventing_historical_change(tmp_path, monkeypatch):
    import database.migrations as migrations
    from tests.historical_migration_helpers import insert_scope

    path = tmp_path / "migration40.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:39])
    initialize_database(path)
    with get_connection(path) as connection:
        scope = insert_scope(connection, scope_type="PUBLIC_IPV4", target="8.8.8.8", name="12D target",
                             stamp="2026-10-13T13:00:00")
    device = create_scope_device(scope["id"], first_seen="2026-10-13T13:00:00",
                                 last_seen="2026-10-13T13:00:00", status="ONLINE", db_path=path)
    at = datetime(2026, 10, 13, 13, 10, 0)
    at_text = at.isoformat(timespec="seconds")
    with get_connection(path) as connection:
        connection.execute(
            """INSERT INTO external_exposures (
                stable_key, scope_id, scope_type, canonical_target, device_id, target_ip,
                port_number, transport, service_name, product, version, extra_info,
                service_confidence, first_seen, last_seen, last_observation_source,
                last_scanner, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"scope:{scope['id']}:ipv4:8.8.8.8:tcp:443", scope["id"], "PUBLIC_IPV4",
                "8.8.8.8", device["id"], "8.8.8.8", 443, "tcp", "https", "nginx", "1.0",
                None, "HIGH", at_text, at_text, "12d-migration", "bounded-test-scanner",
                at_text, at_text,
            ),
        )

    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:40])
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 40
        assert connection.execute("SELECT presence_state FROM external_exposure_presence").fetchone()[0] == "PRESENT"
        assert connection.execute("SELECT COUNT(*) FROM external_exposure_changes").fetchone()[0] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='management_audit_events'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
