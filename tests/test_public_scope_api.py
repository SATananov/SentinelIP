import sqlite3
from datetime import datetime

from fastapi.testclient import TestClient

import api.main as api_main
from database.db import get_connection, initialize_database
from database.scopes import update_scope_enabled
from services.cve_correlation import CveCorrelationService
from services.cve_models import CveRecord, CveServiceEvidence
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from services.scan_models import HostDiscoveryResult, ScanResult
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)


def _client(monkeypatch, tmp_path):
    path = tmp_path / "public-scope-api.db"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    return TestClient(api_main.app), path


def _create(client, target="8.8.8.8", confirmed=True):
    return client.post(
        "/scopes/public-ipv4",
        json={
            "target": target,
            "name": "Approved endpoint",
            "description": "Synthetic authorization test",
            "authorization_confirmed": confirmed,
            "authorization_confirmation_version": PUBLIC_IPV4_CONFIRMATION_VERSION,
        },
    )


def _mock_public_scanners(monkeypatch):
    observed_at = datetime(2026, 10, 12, 10, 30)

    class FakeHostScanner:
        def discover_public_host(self, target):
            assert target == "8.8.8.8"
            return ScanResult(
                target_network=target,
                scanner="mock",
                started_at=observed_at,
                completed_at=observed_at,
                hosts=(
                    HostDiscoveryResult(
                        ip_address=target,
                        discovered_at=observed_at,
                        source="mock-public-target",
                    ),
                ),
            )

    class FakeServiceScanner:
        def discover_public_services(self, target):
            assert target == "8.8.8.8"
            ports = tuple(
                PortObservation(
                    ip_address=target,
                    port=number,
                    transport="tcp",
                    state="open",
                    observed_at=observed_at,
                    source="mock-public-target",
                )
                for number in (22, 23)
            )
            services = (
                ServiceObservation(
                    ip_address=target,
                    port=22,
                    transport="tcp",
                    service_name="ssh",
                    product="OpenSSH",
                    version="9.6",
                    extra_info=None,
                    confidence="HIGH",
                    observed_at=observed_at,
                    source="mock-public-target",
                ),
                ServiceObservation(
                    ip_address=target,
                    port=23,
                    transport="tcp",
                    service_name="telnet",
                    product=None,
                    version=None,
                    extra_info=None,
                    confidence="LOW",
                    observed_at=observed_at,
                    source="mock-public-target",
                ),
            )
            return ServiceDiscoveryResult(
                target_ip=target,
                scanner="mock",
                started_at=observed_at,
                completed_at=observed_at,
                ports=ports,
                services=services,
            )

    monkeypatch.setattr(api_main, "NmapHostDiscoveryScanner", FakeHostScanner)
    monkeypatch.setattr(api_main, "NmapServiceDiscoveryScanner", FakeServiceScanner)


def test_public_ipv4_create_read_duplicate_and_policy(monkeypatch, tmp_path):
    client, path = _client(monkeypatch, tmp_path)

    assert _create(client, confirmed=False).status_code == 422
    assert _create(client, target="192.168.1.1").status_code == 422
    created = _create(client, target=" 8.8.8.8 ")
    assert created.status_code == 201
    scope = created.json()
    assert scope["scope_type"] == "PUBLIC_IPV4"
    assert scope["canonical_target"] == "8.8.8.8"
    assert scope["authorized"] is True and scope["enabled"] is True
    assert scope["authorization_confirmed_at"]
    assert scope["authorization_confirmation_version"] == PUBLIC_IPV4_CONFIRMATION_VERSION
    assert scope["authorization_source"] == "api_explicit_authorization_confirmation"
    assert scope["network_id"] is None
    assert _create(client).status_code == 409
    assert client.get("/scopes").json() == [scope]
    assert client.get(f"/scopes/{scope['id']}").json() == scope
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM networks").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM authorized_scopes").fetchone()[0] == 1


def test_public_scope_scan_persists_scope_linked_review_inventory(
    monkeypatch, tmp_path
):
    client, path = _client(monkeypatch, tmp_path)
    scope = _create(client).json()
    _mock_public_scanners(monkeypatch)

    response = client.post(f"/scopes/{scope['id']}/discover")

    assert response.status_code == 200
    result = response.json()
    assert result["state"] == "OBSERVED"
    assert result["target"] == "8.8.8.8"
    device = result["device"]
    assert device["network_id"] is None
    assert device["scope_id"] == scope["id"]
    assert device["stable_key"] == f"scope:{scope['id']}:ipv4:8.8.8.8"
    assert [port["port_number"] for port in result["ports"]] == [22, 23]
    assert {service["service_name"] for service in result["services"]} == {"ssh", "telnet"}
    assert result["findings"][0]["finding_type"] == "PLAINTEXT_SERVICE"
    assert result["findings"][0]["network_id"] is None
    assert result["findings"][0]["scope_id"] == scope["id"]
    assert result["cve_matches"] == []

    assert client.get(f"/scopes/{scope['id']}/devices").json() == [device]
    assert client.get(f"/devices/{device['id']}/ports").json() == result["ports"]
    assert client.get(f"/devices/{device['id']}/services").json() == result["services"]
    assert client.get(f"/devices/{device['id']}/findings").json() == result["findings"]
    assert client.get(f"/devices/{device['id']}/cve-matches").json() == []
    service_refresh = client.post(
        f"/scopes/{scope['id']}/devices/{device['id']}/discover-services"
    )
    assert service_refresh.status_code == 200
    assert service_refresh.json()["scope_id"] == scope["id"]
    assert service_refresh.json()["device_id"] == device["id"]

    ssh_service = next(item for item in result["services"] if item["service_name"] == "ssh")
    cve_matches = CveCorrelationService(path).correlate(
        CveServiceEvidence(
            service_id=ssh_service["id"],
            device_id=device["id"],
            port_id=ssh_service["port_id"],
            product="OpenSSH",
            version="9.6",
            confidence="HIGH",
            source="mock-public-target",
            observed_at=datetime.fromisoformat(ssh_service["last_seen"]),
        ),
        [
            CveRecord(
                cve_id="CVE-2099-0042",
                source="local-test-fixture",
                product="OpenSSH",
                affected_version_expression=">=9.0,<9.7",
            )
        ],
    )
    assert cve_matches[0]["status"] == "REVIEW"
    review_findings = client.get(f"/devices/{device['id']}/findings").json()
    cve_finding = next(item for item in review_findings if item["finding_type"] == "CVE_REVIEW")
    assert cve_finding["network_id"] is None
    assert cve_finding["scope_id"] == scope["id"]
    assert client.get(f"/devices/{device['id']}/cve-matches").json() == cve_matches
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM networks").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM scope_device_observations WHERE scope_id=?",
            (scope["id"],),
        ).fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_public_scope_gates_before_scanner(monkeypatch, tmp_path):
    client, path = _client(monkeypatch, tmp_path)
    scope = _create(client).json()
    update_scope_enabled(scope["id"], False, path)

    class ForbiddenScanner:
        def __init__(self):
            raise AssertionError("scanner must not be constructed for a disabled scope")

    monkeypatch.setattr(api_main, "NmapHostDiscoveryScanner", ForbiddenScanner)
    response = client.post(f"/scopes/{scope['id']}/discover")

    assert response.status_code == 403
    assert "disabled" in response.json()["detail"]


def test_public_scope_rejects_wrong_type_unconfirmed_and_invalid_target(
    monkeypatch, tmp_path
):
    client, path = _client(monkeypatch, tmp_path)
    scope_id = _create(client).json()["id"]
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE authorized_scopes SET scope_type='PRIVATE_NETWORK' WHERE id=?",
            (scope_id,),
        )
    wrong_type = client.post(f"/scopes/{scope_id}/discover")
    assert wrong_type.status_code == 403

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE authorized_scopes SET scope_type='PUBLIC_IPV4', authorized=0 WHERE id=?",
            (scope_id,),
        )
    unconfirmed = client.post(f"/scopes/{scope_id}/discover")
    assert unconfirmed.status_code == 403

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE authorized_scopes SET authorized=1, canonical_target='192.168.1.1' WHERE id=?",
            (scope_id,),
        )
    invalid_target = client.post(f"/scopes/{scope_id}/discover")
    assert invalid_target.status_code == 403


def test_public_scan_endpoint_accepts_only_scope_id(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    operation = client.get("/openapi.json").json()["paths"]["/scopes/{scope_id}/discover"]["post"]
    assert [parameter["name"] for parameter in operation.get("parameters", [])] == ["scope_id"]
    assert "requestBody" not in operation
