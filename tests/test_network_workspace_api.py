from datetime import datetime, timezone

import api.main as api_main
from database.db import initialize_database
from database.networks import create_network
from local_operator_client import make_local_test_client


def _client_with_db(monkeypatch, tmp_path):
    db_path = tmp_path / "workspace.db"
    initialize_database(db_path)
    monkeypatch.setattr(api_main, "DB_PATH", db_path)
    return make_local_test_client(api_main.app), db_path


def test_list_network_devices_empty(monkeypatch, tmp_path):
    client, db_path = _client_with_db(monkeypatch, tmp_path)
    network = create_network(
        cidr="192.168.50.0/24",
        name="Lab",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )

    response = client.get(f"/networks/{network['id']}/devices")

    assert response.status_code == 200
    assert response.json() == []


def test_discovery_route_returns_discovered_devices(monkeypatch, tmp_path):
    client, db_path = _client_with_db(monkeypatch, tmp_path)
    network = create_network(
        cidr="192.168.60.0/24",
        name="Lab",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )

    observed_at = datetime(2026, 10, 12, 7, 0, tzinfo=timezone.utc).isoformat()

    def fake_discover(stored_network):
        assert stored_network["id"] == network["id"]
        return [
            {
                "id": 7,
                "network_id": network["id"],
                "stable_key": f"network:{network['id']}:ip:192.168.60.10",
                "identity_confidence": "LOW",
                "last_ip_address": "192.168.60.10",
                "mac_address": None,
                "hostname": None,
                "vendor": None,
                "status": "ONLINE",
                "first_seen": observed_at,
                "last_seen": observed_at,
            }
        ]

    monkeypatch.setattr(api_main, "_workspace_discover", fake_discover)

    response = client.post(f"/networks/{network['id']}/discover")

    assert response.status_code == 200
    payload = response.json()
    assert payload["network_id"] == network["id"]
    assert payload["cidr"] == "192.168.60.0/24"
    assert payload["device_count"] == 1
    assert payload["devices"][0]["last_ip_address"] == "192.168.60.10"


def test_workspace_routes_return_404_for_missing_network(monkeypatch, tmp_path):
    client, _ = _client_with_db(monkeypatch, tmp_path)

    assert client.get("/networks/999/devices").status_code == 404
    assert client.post("/networks/999/discover").status_code == 404


def test_discovery_route_maps_scanner_unavailable(monkeypatch, tmp_path):
    client, db_path = _client_with_db(monkeypatch, tmp_path)
    network = create_network(
        cidr="192.168.70.0/24",
        name="Lab",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )

    def fail_discover(_network):
        raise api_main.ScannerUnavailableError("nmap unavailable")

    monkeypatch.setattr(api_main, "_workspace_discover", fail_discover)

    response = client.post(f"/networks/{network['id']}/discover")

    assert response.status_code == 503
    assert response.json()["detail"] == "nmap unavailable"
