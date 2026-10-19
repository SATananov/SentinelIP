import pytest

import api.main as api_main
from database.db import initialize_database
from local_operator_client import make_local_test_client


@pytest.fixture
def client(monkeypatch, tmp_path):
    db_path = tmp_path / "network-api.db"
    initialize_database(db_path)
    monkeypatch.setattr(api_main, "DB_PATH", db_path)
    return make_local_test_client(api_main.app)


def test_list_networks_empty(client):
    response = client.get("/networks")

    assert response.status_code == 200
    assert response.json() == []


def test_create_authorized_network(client):
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


def test_network_api_rejects_unsafe_configuration(client):
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


def test_network_api_requires_explicit_authorization(client):
    response = client.post(
        "/networks",
        json={
            "cidr": "192.168.0.0/24",
            "authorized": False,
            "enabled": True,
        },
    )

    assert response.status_code == 422


def test_network_api_rejects_duplicate_cidr(client):
    payload = {
        "cidr": "192.168.0.0/24",
        "authorized": True,
        "enabled": True,
    }

    assert client.post("/networks", json=payload).status_code == 201
    response = client.post("/networks", json=payload)

    assert response.status_code == 409


def test_get_patch_and_delete_network(client):
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


def test_network_api_returns_404_for_missing_network(client):
    assert client.get("/networks/999999").status_code == 404
    assert client.patch("/networks/999999", json={}).status_code == 404
    assert client.delete("/networks/999999").status_code == 404


def test_network_api_rejects_cidr_update_field(client):
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


def test_network_api_rejects_null_update_value(client):
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


def test_existing_api_endpoints_remain_available(client):
    assert client.get("/health").status_code == 200
    assert client.get("/events?limit=1").status_code == 200
