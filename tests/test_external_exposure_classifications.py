from datetime import datetime


import api.main as api
from database import external_exposure_classifications as classification_db
from database.db import get_connection, initialize_database
from database.inventory import create_scope_device
from database.scopes import create_scope
from services.external_exposure_classification_rules import classify_exposure_rule
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from services.service_inventory import ServiceInventoryService
from local_operator_client import make_local_test_client
from services.service_models import PortObservation, ServiceDiscoveryResult, ServiceObservation


def _scope_device(path):
    scope = create_scope(
        scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8", name="12C target", description="fixture",
        authorized=True, enabled=True, authorization_confirmed_at="2026-10-13T12:00:00",
        authorization_confirmation_version=PUBLIC_IPV4_CONFIRMATION_VERSION,
        authorization_source="test_explicit_authorization", db_path=path,
    )
    device = create_scope_device(scope["id"], first_seen="2026-10-13T12:00:00",
        last_seen="2026-10-13T12:00:00", status="ONLINE", db_path=path)
    return scope, device


def _result(port, service_name=None):
    at = datetime(2026, 10, 13, 12, 15, 0)
    services = () if service_name is None else (
        ServiceObservation("8.8.8.8", port, "tcp", service_name, None, None, None, "MEDIUM", at, "12c-test"),
    )
    return ServiceDiscoveryResult(
        target_ip="8.8.8.8", scanner="bounded-test-scanner", started_at=at, completed_at=at,
        ports=(PortObservation("8.8.8.8", port, "tcp", "open", at, "12c-test"),),
        services=services,
    )


def test_deterministic_role_and_profile_rules_do_not_claim_vulnerability():
    cases = [
        (22, "ssh", "REMOTE_ADMIN", "SENSITIVE_ADMIN_SERVICE"),
        (443, "https", "WEB", "COMMON_PUBLIC_SERVICE"),
        (445, "microsoft-ds", "FILE_SHARING", "INTERNAL_STYLE_SERVICE"),
        (5432, "postgresql", "DATABASE", "INTERNAL_STYLE_SERVICE"),
        (25, "smtp", "MAIL", "COMMON_PUBLIC_SERVICE"),
        (53, "domain", "DNS", "COMMON_PUBLIC_SERVICE"),
        (1194, "openvpn", "VPN", "COMMON_PUBLIC_SERVICE"),
        (65000, "custom-service", "OTHER", "UNKNOWN_SERVICE"),
        (65001, None, "UNKNOWN", "UNKNOWN_SERVICE"),
    ]
    for port, name, role, profile in cases:
        decision = classify_exposure_rule({"port_number": port, "service_name": name})
        assert (decision.service_role, decision.exposure_profile) == (role, profile)
        assert "not a vulnerability finding" in decision.reason.lower()


def test_public_inventory_creates_and_updates_classification(tmp_path):
    path = tmp_path / "classification.db"; initialize_database(path)
    scope, device = _scope_device(path)
    ServiceInventoryService(path).process_public_result(scope, device, _result(22, "ssh"))
    result = classification_db.query_classifications(scope_id=scope["id"], db_path=path)
    assert result["total"] == 1
    item = result["items"][0]
    assert item["service_role"] == "REMOTE_ADMIN"
    assert item["exposure_profile"] == "SENSITIVE_ADMIN_SERVICE"
    assert item["target_ip"] == "8.8.8.8" and item["port_number"] == 22


def test_classification_api_is_read_only_and_filterable(monkeypatch, tmp_path):
    path = tmp_path / "classification-api.db"; initialize_database(path)
    scope, device = _scope_device(path)
    ServiceInventoryService(path).process_public_result(scope, device, _result(443, "https"))
    monkeypatch.setattr(api, "DB_PATH", path)
    client = make_local_test_client(api.app)
    response = client.get("/external-exposure-classifications?service_role=WEB&exposure_profile=COMMON_PUBLIC_SERVICE")
    assert response.status_code == 200
    body = response.json(); assert body["total"] == 1 and body["count"] == 1
    cid = body["items"][0]["id"]
    assert client.get(f"/external-exposure-classifications/{cid}").status_code == 200
    assert client.get("/external-exposure-classifications?target_ip=192.168.1.1").status_code == 422
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/external-exposure-classifications"].keys()) == {"get"}
    assert set(paths["/external-exposure-classifications/{classification_id}"].keys()) == {"get"}


def test_migration_39_backfills_existing_exposure_and_is_idempotent(tmp_path, monkeypatch):
    import database.migrations as migrations
    from tests.historical_migration_helpers import insert_scope
    path = tmp_path / "migration39.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:38])
    initialize_database(path)
    with get_connection(path) as connection:
        scope = insert_scope(connection, scope_type="PUBLIC_IPV4", target="8.8.8.8", name="12C target",
                             stamp="2026-10-13T12:00:00")
    device = create_scope_device(scope["id"], first_seen="2026-10-13T12:00:00",
                                 last_seen="2026-10-13T12:00:00", status="ONLINE", db_path=path)
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
                "8.8.8.8", device["id"], "8.8.8.8", 443, "tcp", "https", None, None, None,
                "MEDIUM", "2026-10-13T12:15:00", "2026-10-13T12:15:00", "12c-migration",
                "bounded-test-scanner", "2026-10-13T12:15:00", "2026-10-13T12:15:00",
            ),
        )
    # 12C table does not exist yet; factual 12A + 12B evidence does.
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:39])
    initialize_database(path); initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 39
        row = connection.execute("SELECT service_role, exposure_profile FROM external_exposure_classifications").fetchone()
        assert row == ("WEB", "COMMON_PUBLIC_SERVICE")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 44
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='management_audit_events'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
