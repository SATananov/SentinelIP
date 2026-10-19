import sqlite3

import api.main as api_main
from database.db import get_connection, initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.scopes import get_scope_for_network, update_scope_enabled
from local_operator_client import make_local_test_client


def _scope_client(monkeypatch, tmp_path):
    path = tmp_path / "scopes-api.db"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    network = create_network("192.168.30.0/24", "Lab", "", True, True, path)
    device = create_device(
        stable_key=f"network:{network['id']}:ip:192.168.30.8",
        network_id=network["id"],
        mac_address=None,
        hostname=None,
        vendor=None,
        first_seen="2026-10-12T10:00:00",
        last_seen="2026-10-12T10:00:00",
        last_ip_address="192.168.30.8",
        status="ONLINE",
        identity_confidence="LOW",
        db_path=path,
    )
    return make_local_test_client(api_main.app), path, network, device


def test_scope_read_api_and_network_scope_association_are_read_only(
    monkeypatch, tmp_path
):
    client, path, network, _ = _scope_client(monkeypatch, tmp_path)
    scope = get_scope_for_network(network["id"], path)
    with get_connection(path) as connection:
        before = (
            connection.execute("SELECT COUNT(*) FROM networks").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM authorized_scopes").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM network_scope_links").fetchone()[0],
        )

    listing = client.get("/scopes")
    detail = client.get(f"/scopes/{scope['id']}")

    assert listing.status_code == 200
    assert listing.json() == [scope]
    assert detail.status_code == 200
    assert detail.json() == scope
    assert client.get("/scopes/999999").status_code == 404
    with get_connection(path) as connection:
        after = (
            connection.execute("SELECT COUNT(*) FROM networks").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM authorized_scopes").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM network_scope_links").fetchone()[0],
        )
    assert after == before
    assert not any(
        route.path in {"/scopes", "/scopes/{scope_id}"}
        and "POST" in (route.methods or set())
        for route in api_main.app.routes
    )


def test_network_scan_requires_enabled_scope(monkeypatch, tmp_path):
    client, path, network, _ = _scope_client(monkeypatch, tmp_path)
    update_scope_enabled(get_scope_for_network(network["id"], path)["id"], False, path)

    def unexpected_scan(*_args):
        raise AssertionError("scanner must not run when scope is disabled")

    monkeypatch.setattr(api_main, "_workspace_discover", unexpected_scan)
    response = client.post(f"/networks/{network['id']}/discover")

    assert response.status_code == 403
    assert "disabled" in response.json()["detail"]


def test_service_scan_requires_confirmed_associated_scope(monkeypatch, tmp_path):
    client, path, network, device = _scope_client(monkeypatch, tmp_path)
    scope = get_scope_for_network(network["id"], path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE authorized_scopes SET authorized=0 WHERE id=?", (scope["id"],)
        )

    def unexpected_scan(*_args):
        raise AssertionError("scanner must not run for an unconfirmed scope")

    monkeypatch.setattr(api_main, "_workspace_discover_services", unexpected_scan)
    response = client.post(f"/devices/{device['id']}/discover-services")

    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]


def test_wrong_scope_type_blocks_network_scan(monkeypatch, tmp_path):
    client, path, network, _ = _scope_client(monkeypatch, tmp_path)
    scope = get_scope_for_network(network["id"], path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE authorized_scopes SET scope_type='HOSTNAME' WHERE id=?",
            (scope["id"],),
        )

    response = client.post(f"/networks/{network['id']}/discover")

    assert response.status_code == 403
    assert "not private" in response.json()["detail"]
