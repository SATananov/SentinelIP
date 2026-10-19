from fastapi.testclient import TestClient
import pytest

import api.main as api_main
from database.db import get_connection, initialize_database
from database.management_audit import record_event
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from local_operator_client import make_local_test_client


PROTECTED_ROUTE_METHODS = {
    ("GET", "/networks"), ("POST", "/networks"),
    ("GET", "/networks/{network_id}"), ("PATCH", "/networks/{network_id}"),
    ("DELETE", "/networks/{network_id}"),
    ("POST", "/networks/{network_id}/discover"),
    ("GET", "/scopes"), ("GET", "/scopes/{scope_id}"),
    ("GET", "/scopes/{scope_id}/devices"),
    ("POST", "/scopes/public-ipv4"), ("POST", "/scopes/public-cidr"),
    ("POST", "/scopes/public-cidr/preview"), ("POST", "/scopes/hostname"),
    ("POST", "/scopes/hostname/preview"),
    ("POST", "/scopes/{scope_id}/hostname/reauthorize"),
    ("POST", "/scopes/{scope_id}/discover"),
    ("POST", "/scopes/{scope_id}/devices/{device_id}/discover-services"),
    ("POST", "/devices/{device_id}/discover-services"),
    ("GET", "/scopes/{scope_id}/external-exposure-policy"),
    ("PUT", "/scopes/{scope_id}/external-exposure-policy"),
    ("DELETE", "/scopes/{scope_id}/external-exposure-policy"),
}


@pytest.fixture
def control_plane_client(monkeypatch, tmp_path):
    path = tmp_path / "control-plane.db"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    return make_local_test_client(api_main.app), path


def test_every_21b_route_has_the_existing_local_management_dependency():
    registered = set()
    for route in api_main.app.routes:
        if not getattr(route, "methods", None):
            continue
        for method in route.methods:
            pair = (method, route.path)
            if pair in PROTECTED_ROUTE_METHODS:
                registered.add(pair)
                assert any(dependency.call.__name__ == "local_management"
                           for dependency in route.dependant.dependencies), pair
    assert registered == PROTECTED_ROUTE_METHODS


@pytest.mark.parametrize("method,path", [
    ("GET", "/networks"),
    ("GET", "/scopes"),
    ("POST", "/scopes/public-cidr/preview"),
    ("POST", "/networks/1/discover"),
    ("GET", "/scopes/1/external-exposure-policy"),
])
def test_control_plane_route_denies_non_loopback_peer(control_plane_client, method, path):
    _, _ = control_plane_client
    client = TestClient(api_main.app, base_url="http://127.0.0.1:8000",
                        client=("192.0.2.20", 4000))
    response = client.request(method, path, json={"target": "8.8.8.0/24"} if method == "POST" else None)
    assert response.status_code == 403


@pytest.mark.parametrize("base_url,headers", [
    ("http://operator.example", {}),
    ("http://127.0.0.1", {"Origin": "https://operator.example"}),
    ("http://127.0.0.1", {"Forwarded": "for=127.0.0.1"}),
    ("http://127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}),
    ("http://127.0.0.1", {"X-Forwarded-Host": "127.0.0.1"}),
    ("http://127.0.0.1", {"Authorization": "Bearer token"}),
    ("http://127.0.0.1", {"X-Sensor-UUID": "sensor"}),
    ("http://127.0.0.1", {"X-SentinelIP-Sensor-ID": "sensor"}),
    ("http://127.0.0.1", {"X-SentinelIP-Sensor-Token": "token"}),
])
def test_control_plane_route_reuses_existing_header_host_and_origin_denials(
        control_plane_client, base_url, headers):
    client, _ = control_plane_client
    denied_client = TestClient(api_main.app, base_url=base_url,
                               client=("127.0.0.1", 4000))
    response = denied_client.get("/networks", headers=headers)
    assert response.status_code == 403


def test_allowed_local_origins_and_cli_style_requests_are_accepted(control_plane_client):
    client, _ = control_plane_client
    assert client.get("/networks").status_code == 200  # No Origin, loopback Host/peer.
    for origin in ("http://127.0.0.1:5173", "http://localhost:5173"):
        response = client.get("/networks", headers={"Origin": origin})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"


def test_new_control_plane_audit_events_use_local_operator(control_plane_client):
    client, path = control_plane_client
    network = client.post("/networks", json={
        "cidr": "192.168.90.0/24", "name": "Boundary test", "description": "",
        "authorized": True, "enabled": True,
    })
    assert network.status_code == 201
    network_id = network.json()["id"]
    assert client.patch(f"/networks/{network_id}", json={"enabled": False}).status_code == 200
    assert client.delete(f"/networks/{network_id}").status_code == 204

    scope = client.post("/scopes/public-ipv4", json={
        "target": "8.8.8.8", "name": "Boundary target", "description": "",
        "authorization_confirmed": True,
        "authorization_confirmation_version": PUBLIC_IPV4_CONFIRMATION_VERSION,
    })
    assert scope.status_code == 201
    scope_id = scope.json()["id"]
    assert client.put(f"/scopes/{scope_id}/external-exposure-policy",
                      json={"expected_tcp_ports": [443]}).status_code == 200
    assert client.delete(f"/scopes/{scope_id}/external-exposure-policy").status_code == 204

    with get_connection(path) as connection:
        actors = connection.execute(
            "SELECT event_type, actor_type FROM management_audit_events ORDER BY id"
        ).fetchall()
    assert [tuple(row) for row in actors] == [
        ("NETWORK_CREATED", "LOCAL_OPERATOR"),
        ("NETWORK_DISABLED", "LOCAL_OPERATOR"),
        ("NETWORK_DELETED", "LOCAL_OPERATOR"),
        ("SCOPE_AUTHORIZED", "LOCAL_OPERATOR"),
        ("EXPOSURE_POLICY_CONFIGURED", "LOCAL_OPERATOR"),
        ("EXPOSURE_POLICY_REMOVED", "LOCAL_OPERATOR"),
    ]


def test_historical_api_client_actor_rows_remain_valid(control_plane_client):
    _, path = control_plane_client
    with get_connection(path) as connection:
        record_event(connection, event_type="NETWORK_DELETED", entity_type="NETWORK",
                     entity_id=99, actor_type="API_CLIENT", previous_state="DISABLED")
    with get_connection(path) as connection:
        row = connection.execute(
            "SELECT actor_type FROM management_audit_events WHERE entity_id='99'"
        ).fetchone()
    assert row[0] == "API_CLIENT"
