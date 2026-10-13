from datetime import datetime

from fastapi.testclient import TestClient

import api.main as api
from database import external_exposure_assessments as assessment_db
from database.db import get_connection, initialize_database
from database.inventory import create_scope_device
from database.scopes import create_scope
from services.external_exposure_assessment import configure_scope_policy
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from services.service_inventory import ServiceInventoryService
from services.service_models import PortObservation, ServiceDiscoveryResult, ServiceObservation


def _scope_and_device(path, target="8.8.8.8"):
    scope = create_scope(
        scope_type="PUBLIC_IPV4",
        canonical_target=target,
        name="Assessment target",
        description="12B fixture",
        authorized=True,
        enabled=True,
        authorization_confirmed_at="2026-10-13T11:00:00",
        authorization_confirmation_version=PUBLIC_IPV4_CONFIRMATION_VERSION,
        authorization_source="test_explicit_authorization",
        db_path=path,
    )
    device = create_scope_device(
        scope["id"], first_seen="2026-10-13T11:00:00", last_seen="2026-10-13T11:00:00",
        status="ONLINE", db_path=path,
    )
    return scope, device


def _result(at):
    return ServiceDiscoveryResult(
        target_ip="8.8.8.8",
        scanner="bounded-test-scanner",
        started_at=at,
        completed_at=at,
        ports=(
            PortObservation("8.8.8.8", 22, "tcp", "open", at, "12b-test"),
            PortObservation("8.8.8.8", 443, "tcp", "open", at, "12b-test"),
        ),
        services=(
            ServiceObservation(
                "8.8.8.8", 22, "tcp", "ssh", "OpenSSH", "9.7", None,
                "HIGH", at, "12b-test",
            ),
        ),
    )


def test_public_exposures_default_to_review_without_explicit_policy(tmp_path):
    path = tmp_path / "assessment-review.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    ServiceInventoryService(path).process_public_result(
        scope, device, _result(datetime(2026, 10, 13, 11, 10, 0))
    )

    result = assessment_db.query_assessments(scope_id=scope["id"], db_path=path)
    assert result["total"] == 2
    assert {item["classification"] for item in result["items"]} == {"REVIEW"}
    assert {item["rule_id"] for item in result["items"]} == {"NO_EXPLICIT_EXPOSURE_POLICY"}
    assert all(item["policy_id"] is None for item in result["items"])


def test_explicit_expected_port_allowlist_classifies_expected_and_unexpected(tmp_path):
    path = tmp_path / "assessment-policy.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    ServiceInventoryService(path).process_public_result(
        scope, device, _result(datetime(2026, 10, 13, 11, 10, 0))
    )

    policy = configure_scope_policy(scope["id"], [443], path)
    assert policy["expected_tcp_ports"] == [443]
    result = assessment_db.query_assessments(scope_id=scope["id"], db_path=path)
    by_port = {item["port_number"]: item for item in result["items"]}
    assert by_port[443]["classification"] == "EXPECTED"
    assert by_port[443]["rule_id"] == "PORT_DECLARED_EXPECTED"
    assert by_port[22]["classification"] == "UNEXPECTED"
    assert by_port[22]["rule_id"] == "PORT_NOT_DECLARED_EXPECTED"
    assert by_port[22]["policy_id"] == policy["id"]


def test_policy_api_is_bounded_public_scope_configuration_and_assessment_api_is_read_only(monkeypatch, tmp_path):
    path = tmp_path / "assessment-api.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    ServiceInventoryService(path).process_public_result(
        scope, device, _result(datetime(2026, 10, 13, 11, 10, 0))
    )
    private = create_scope(
        scope_type="PRIVATE_NETWORK", canonical_target="192.168.50.0/24",
        name="Private", description="Not assessable", authorized=True, enabled=True,
        authorization_confirmed_at="2026-10-13T11:00:00",
        authorization_confirmation_version="private-network-authorization-v1",
        authorization_source="test", db_path=path,
    )
    monkeypatch.setattr(api, "DB_PATH", path)
    client = TestClient(api.app)

    saved = client.put(
        f"/scopes/{scope['id']}/external-exposure-policy",
        json={"expected_tcp_ports": [443]},
    )
    assert saved.status_code == 200 and saved.json()["expected_tcp_ports"] == [443]
    assert client.get(f"/scopes/{scope['id']}/external-exposure-policy").status_code == 200
    assert client.put(
        f"/scopes/{scope['id']}/external-exposure-policy",
        json={"expected_tcp_ports": [443], "target": "1.1.1.1"},
    ).status_code == 422
    assert client.put(
        f"/scopes/{private['id']}/external-exposure-policy",
        json={"expected_tcp_ports": [22]},
    ).status_code == 422

    listing = client.get("/external-exposure-assessments?classification=UNEXPECTED")
    assert listing.status_code == 200 and listing.json()["total"] == 1
    assessment = listing.json()["items"][0]
    assert assessment["port_number"] == 22 and assessment["target_ip"] == "8.8.8.8"
    assert client.get(f"/external-exposure-assessments/{assessment['id']}").status_code == 200
    assert client.get("/external-exposure-assessments?target_ip=192.168.1.1").status_code == 422

    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/external-exposure-assessments"].keys()) == {"get"}
    assert set(paths["/external-exposure-assessments/{assessment_id}"].keys()) == {"get"}


def test_removing_explicit_policy_reverts_existing_exposures_to_review(monkeypatch, tmp_path):
    path = tmp_path / "assessment-delete.db"
    initialize_database(path)
    scope, device = _scope_and_device(path)
    ServiceInventoryService(path).process_public_result(
        scope, device, _result(datetime(2026, 10, 13, 11, 10, 0))
    )
    configure_scope_policy(scope["id"], [443], path)
    monkeypatch.setattr(api, "DB_PATH", path)
    client = TestClient(api.app)

    response = client.delete(f"/scopes/{scope['id']}/external-exposure-policy")
    assert response.status_code == 204
    result = assessment_db.query_assessments(scope_id=scope["id"], db_path=path)
    assert {item["classification"] for item in result["items"]} == {"REVIEW"}
    assert all(item["policy_id"] is None for item in result["items"])


def test_migration_38_is_additive_idempotent_and_fk_clean(tmp_path, monkeypatch):
    import database.migrations as migrations

    path = tmp_path / "migration-38.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:37])
    initialize_database(path)
    scope, device = _scope_and_device(path)
    # Seed one valid 12A exposure directly against the pre-38 schema so the
    # migration test proves that existing factual exposure evidence survives.
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
                "MEDIUM", "2026-10-13T11:10:00", "2026-10-13T11:10:00", "12b-migration",
                "bounded-test-scanner", "2026-10-13T11:10:00", "2026-10-13T11:10:00",
            ),
        )
        assert connection.execute("SELECT COUNT(*) FROM external_exposures").fetchone()[0] == 1

    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:38])
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 38
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"external_exposure_policies", "external_exposure_assessments"} <= tables
        assert connection.execute("SELECT COUNT(*) FROM external_exposures").fetchone()[0] == 1
        assessment = connection.execute(
            "SELECT classification, rule_id FROM external_exposure_assessments"
        ).fetchone()
        assert assessment == ("REVIEW", "NO_EXPLICIT_EXPOSURE_POLICY")
        assert connection.execute("SELECT id FROM devices WHERE id=?", (device["id"],)).fetchone()
        assert connection.execute("SELECT id FROM authorized_scopes WHERE id=?", (scope["id"],)).fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
