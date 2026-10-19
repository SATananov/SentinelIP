import api.main as api_main
from database.db import initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.services import create_port, create_service
from local_operator_client import make_local_test_client


def _workspace(monkeypatch, tmp_path):
    db_path = tmp_path / "workspace-services.db"
    initialize_database(db_path)
    monkeypatch.setattr(api_main, "DB_PATH", db_path)

    network = create_network(
        cidr="192.168.80.0/24",
        name="Lab",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )

    device = create_device(
        stable_key=f"network:{network['id']}:ip:192.168.80.10",
        network_id=network["id"],
        mac_address=None,
        hostname=None,
        vendor=None,
        first_seen="2026-10-12T08:00:00",
        last_seen="2026-10-12T08:00:00",
        last_ip_address="192.168.80.10",
        status="ONLINE",
        identity_confidence="LOW",
        db_path=db_path,
    )

    return make_local_test_client(api_main.app), db_path, network, device


def test_get_device(monkeypatch, tmp_path):
    client, _, _, device = _workspace(monkeypatch, tmp_path)

    response = client.get(f"/devices/{device['id']}")

    assert response.status_code == 200
    assert response.json()["id"] == device["id"]
    assert response.json()["last_ip_address"] == "192.168.80.10"


def test_device_ports_and_services_read_api(monkeypatch, tmp_path):
    client, db_path, _, device = _workspace(monkeypatch, tmp_path)

    port = create_port(
        device_id=device["id"],
        port_number=22,
        transport="tcp",
        state="open",
        first_seen="2026-10-12T08:00:00",
        last_seen="2026-10-12T08:00:00",
        db_path=db_path,
    )
    create_service(
        device_id=device["id"],
        port_id=port["id"],
        service_name="ssh",
        product="OpenSSH",
        version="9.6",
        extra_info=None,
        confidence="HIGH",
        first_seen="2026-10-12T08:00:00",
        last_seen="2026-10-12T08:00:00",
        db_path=db_path,
    )

    ports = client.get(f"/devices/{device['id']}/ports")
    services = client.get(f"/devices/{device['id']}/services")

    assert ports.status_code == 200
    assert ports.json()[0]["port_number"] == 22

    assert services.status_code == 200
    assert services.json()[0]["service_name"] == "ssh"
    assert services.json()[0]["product"] == "OpenSSH"


def test_findings_and_cve_match_read_api_empty(monkeypatch, tmp_path):
    client, _, _, device = _workspace(monkeypatch, tmp_path)

    findings = client.get(f"/devices/{device['id']}/findings")
    cves = client.get(f"/devices/{device['id']}/cve-matches")

    assert findings.status_code == 200
    assert findings.json() == []

    assert cves.status_code == 200
    assert cves.json() == []


def test_service_discovery_route_returns_persisted_result(
    monkeypatch,
    tmp_path,
):
    client, _, network, device = _workspace(monkeypatch, tmp_path)

    def fake_discover(stored_network, stored_device):
        assert stored_network["id"] == network["id"]
        assert stored_device["id"] == device["id"]
        return {
            "ports": [
                {
                    "id": 10,
                    "device_id": device["id"],
                    "port_number": 445,
                    "transport": "tcp",
                    "state": "open",
                }
            ],
            "services": [
                {
                    "id": 20,
                    "device_id": device["id"],
                    "port_id": 10,
                    "service_name": "microsoft-ds",
                    "product": None,
                    "version": None,
                    "confidence": "LOW",
                }
            ],
        }

    monkeypatch.setattr(api_main, "_workspace_discover_services", fake_discover)

    response = client.post(f"/devices/{device['id']}/discover-services")

    assert response.status_code == 200
    payload = response.json()

    assert payload["device_id"] == device["id"]
    assert payload["network_id"] == network["id"]
    assert payload["ip_address"] == "192.168.80.10"
    assert payload["port_count"] == 1
    assert payload["service_count"] == 1


def test_service_discovery_missing_device_is_404(monkeypatch, tmp_path):
    client, _, _, _ = _workspace(monkeypatch, tmp_path)

    response = client.post("/devices/999/discover-services")

    assert response.status_code == 404


def test_service_discovery_maps_controlled_scanner_failure(
    monkeypatch,
    tmp_path,
):
    client, _, _, device = _workspace(monkeypatch, tmp_path)

    def fail_discover(_network, _device):
        raise api_main.ScannerUnavailableError("nmap unavailable")

    monkeypatch.setattr(
        api_main,
        "_workspace_discover_services",
        fail_discover,
    )

    response = client.post(f"/devices/{device['id']}/discover-services")

    assert response.status_code == 503
    assert response.json()["detail"] == "nmap unavailable"
