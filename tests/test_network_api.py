from fastapi.testclient import TestClient

from api.main import app
from database.networks import delete_network, list_networks


client = TestClient(app)


def clear_networks():
    for network in list_networks():
        delete_network(network["id"])


def test_list_networks_empty():
    clear_networks()

    response = client.get("/networks")

    assert response.status_code == 200
    assert response.json() == []


def test_create_authorized_network():
    clear_networks()

    response = client.post(
        "/networks",
        json={
            "cidr": "192.168.1.1/25",
            "name": "Home LAN",
            "description": "Authorized home network",
            "authorized": True,
            "enabled": True,
        },
    )

    assert response.status_code == 201
    assert response.json()["cidr"] == "192.168.1.0/25"


def test_network_api_rejects_unsafe_configuration():
    clear_networks()

    for cidr in ("8.8.8.0/24", "192.168.0.0/23", "not-a-cidr"):
        response = client.post(
            "/networks",
            json={
                "cidr": cidr,
                "authorized": True,
                "enabled": True,
            },
        )
        assert response.status_code == 422


def test_network_api_requires_explicit_authorization():
    clear_networks()

    response = client.post(
        "/networks",
        json={
            "cidr": "192.168.0.0/24",
            "authorized": False,
            "enabled": True,
        },
    )

    assert response.status_code == 422


def test_network_api_rejects_duplicate_cidr():
    clear_networks()
    payload = {
        "cidr": "192.168.0.0/24",
        "authorized": True,
        "enabled": True,
    }

    assert client.post("/networks", json=payload).status_code == 201
    response = client.post("/networks", json=payload)

    assert response.status_code == 409


def test_get_patch_and_delete_network():
    clear_networks()
    response = client.post(
        "/networks",
        json={
            "cidr": "10.10.10.0/24",
            "name": "Initial",
            "description": "Initial description",
            "authorized": True,
            "enabled": True,
        },
    )
    network_id = response.json()["id"]

    response = client.get(f"/networks/{network_id}")
    assert response.status_code == 200

    response = client.patch(
        f"/networks/{network_id}",
        json={
            "name": "Updated",
            "description": "Updated description",
            "enabled": False,
        },
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Updated"
    assert response.json()["enabled"] is False

    response = client.delete(f"/networks/{network_id}")
    assert response.status_code == 204
    assert client.get(f"/networks/{network_id}").status_code == 404


def test_network_api_returns_404_for_missing_network():
    clear_networks()

    assert client.get("/networks/999999").status_code == 404
    assert client.patch("/networks/999999", json={}).status_code == 404
    assert client.delete("/networks/999999").status_code == 404


def test_network_api_rejects_cidr_update_field():
    clear_networks()
    response = client.post(
        "/networks",
        json={
            "cidr": "192.168.0.0/24",
            "authorized": True,
            "enabled": True,
        },
    )
    network_id = response.json()["id"]

    response = client.patch(
        f"/networks/{network_id}",
        json={"cidr": "192.168.1.0/24"},
    )

    assert response.status_code == 422


def test_network_api_rejects_null_update_value():
    clear_networks()
    response = client.post(
        "/networks",
        json={
            "cidr": "192.168.0.0/24",
            "authorized": True,
            "enabled": True,
        },
    )
    network_id = response.json()["id"]

    response = client.patch(
        f"/networks/{network_id}",
        json={"name": None},
    )

    assert response.status_code == 422


def test_existing_api_endpoints_remain_available():
    assert client.get("/health").status_code == 200
    assert client.get("/events?limit=1").status_code == 200