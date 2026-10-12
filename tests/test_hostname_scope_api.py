from datetime import datetime

from fastapi.testclient import TestClient

import api.main as api_main
from database.db import get_connection, initialize_database
from services.scope_authorization import HOSTNAME_CONFIRMATION_VERSION
from services.scan_models import HostDiscoveryResult, ScanResult
from services.service_models import ServiceDiscoveryResult


ADDRESS_SET = ("8.8.8.8", "8.8.4.4")


class FakeResolver:
    addresses = ADDRESS_SET
    calls = 0

    def resolve(self, hostname):
        from services.hostname_resolution import HostnameResolution

        type(self).calls += 1
        return HostnameResolution(hostname, tuple(sorted(type(self).addresses)))


def _client(monkeypatch, tmp_path):
    path = tmp_path / "hostname-scope.db"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    monkeypatch.setattr(api_main, "HostnameResolver", FakeResolver)
    FakeResolver.addresses = ADDRESS_SET
    FakeResolver.calls = 0
    return TestClient(api_main.app), path


def _create_payload(addresses=None):
    return {
        "canonical_hostname": "example.com",
        "approved_resolved_ipv4": list(addresses or ADDRESS_SET),
        "name": "Example service",
        "description": "Synthetic test scope",
        "authorization_confirmed": True,
        "authorization_confirmation_version": HOSTNAME_CONFIRMATION_VERSION,
    }


def test_preview_is_read_only_and_creation_persists_exact_addresses(monkeypatch, tmp_path):
    client, path = _client(monkeypatch, tmp_path)
    preview = client.post("/scopes/hostname/preview", json={"hostname": "Example.COM."})
    assert preview.status_code == 200
    assert preview.json()["canonical_hostname"] == "example.com"
    assert preview.json()["resolved_ipv4"] == ["8.8.4.4", "8.8.8.8"]
    assert preview.json()["eligible"] is True
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM authorized_scopes").fetchone()[0] == 0

    created = client.post("/scopes/hostname", json=_create_payload())
    assert created.status_code == 201
    scope = created.json()
    assert scope["scope_type"] == "HOSTNAME"
    assert scope["canonical_target"] == "example.com"
    assert scope["approved_addresses"] == ["8.8.4.4", "8.8.8.8"]
    assert scope["resolution_status"] == "CURRENT"
    assert scope["authorization_confirmed_at"]
    assert client.get(f"/scopes/{scope['id']}").json() == scope
    duplicate = client.post("/scopes/hostname", json=_create_payload())
    assert duplicate.status_code == 409
    assert client.post("/scopes/hostname", json={**_create_payload(), "canonical_hostname": "other.example"}).status_code == 201


def test_create_requires_confirmation_and_current_exact_preview(monkeypatch, tmp_path):
    client, path = _client(monkeypatch, tmp_path)
    payload = _create_payload()
    assert client.post("/scopes/hostname", json={**payload, "authorization_confirmed": False}).status_code == 422

    FakeResolver.addresses = ("8.8.8.8",)
    changed = client.post("/scopes/hostname", json=payload)
    assert changed.status_code == 409
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM authorized_scopes").fetchone()[0] == 0


def test_reauthorization_requires_same_hostname_and_persists_new_set(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    scope = client.post("/scopes/hostname", json=_create_payload()).json()
    FakeResolver.addresses = ("1.1.1.1",)
    FakeResolver.calls = 0
    mismatch = client.post(
        f"/scopes/{scope['id']}/hostname/reauthorize",
        json=_create_payload(("1.1.1.1",)) | {"canonical_hostname": "other.example"},
    )
    assert mismatch.status_code == 422
    assert FakeResolver.calls == 0

    renewed = client.post(
        f"/scopes/{scope['id']}/hostname/reauthorize",
        json=_create_payload(("1.1.1.1",)),
    )
    assert renewed.status_code == 200
    assert renewed.json()["approved_addresses"] == ["1.1.1.1"]
    assert renewed.json()["resolution_status"] == "CURRENT"


def test_hostname_scan_uses_only_approved_ips_and_rejects_dns_drift(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    scope = client.post("/scopes/hostname", json=_create_payload()).json()
    seen = []
    observed_at = datetime(2026, 10, 12, 10, 30)

    class FakeHostScanner:
        def discover_public_host(self, target):
            seen.append(target)
            return ScanResult(
                target_network=target,
                scanner="mock",
                started_at=observed_at,
                completed_at=observed_at,
                hosts=(HostDiscoveryResult(ip_address=target, discovered_at=observed_at, source="fixture"),),
            )

    class FakeServiceScanner:
        def discover_public_services(self, target):
            seen.append(target)
            return ServiceDiscoveryResult(
                target_ip=target,
                scanner="mock",
                started_at=observed_at,
                completed_at=observed_at,
                ports=(),
                services=(),
            )

    monkeypatch.setattr(api_main, "NmapHostDiscoveryScanner", FakeHostScanner)
    monkeypatch.setattr(api_main, "NmapServiceDiscoveryScanner", FakeServiceScanner)
    response = client.post(f"/scopes/{scope['id']}/discover", json={"target": "1.1.1.1"})
    assert response.status_code == 200
    assert seen == ["8.8.4.4", "8.8.4.4", "8.8.8.8", "8.8.8.8"]
    assert {device["last_ip_address"] for device in response.json()["devices"]} == set(ADDRESS_SET)
    assert all(device["scope_id"] == scope["id"] and device["network_id"] is None for device in response.json()["devices"])

    seen.clear()
    FakeResolver.addresses = ("8.8.4.4", "1.1.1.1")
    drift = client.post(f"/scopes/{scope['id']}/discover")
    assert drift.status_code == 409
    assert seen == []
    persisted = client.get(f"/scopes/{scope['id']}").json()
    assert persisted["resolution_status"] == "REAUTH_REQUIRED"


def test_hostname_scan_accepts_same_dns_set_in_different_order(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    scope = client.post("/scopes/hostname", json=_create_payload()).json()
    FakeResolver.addresses = tuple(reversed(ADDRESS_SET))

    class NoHostScanner:
        def discover_public_host(self, target):
            return ScanResult(
                target_network=target,
                scanner="mock",
                started_at=datetime(2026, 10, 12),
                completed_at=datetime(2026, 10, 12),
                hosts=(),
            )

    class NoServiceScanner:
        def discover_public_services(self, _target):
            raise AssertionError("no service scan without observed host")

    monkeypatch.setattr(api_main, "NmapHostDiscoveryScanner", NoHostScanner)
    monkeypatch.setattr(api_main, "NmapServiceDiscoveryScanner", NoServiceScanner)
    result = client.post(f"/scopes/{scope['id']}/discover")
    assert result.status_code == 200
    assert result.json()["state"] == "NOT_OBSERVED"
