import sqlite3
from unittest.mock import Mock

import api.main as api_main
from database.db import initialize_database
from local_operator_client import make_local_test_client
from database.networks import create_network, list_networks
from services.local_network_discovery import (
    LocalNetworkCandidate,
    LocalNetworkDiscoveryError,
)


def make_candidate():
    return LocalNetworkCandidate(
        cidr="192.168.0.0/24",
        interface="wlan0",
        source="connected_route+interface_address",
        address="192.168.0.158",
        prefix_length=24,
        operstate="UP",
        route_scope="link",
        evidence=(
            "assigned IPv4 address 192.168.0.158/24",
            "directly connected IPv4 route 192.168.0.0/24",
        ),
    )


def table_row_counts(db_path):
    with sqlite3.connect(db_path) as connection:
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            name: connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            for name in names
        }


def test_network_candidates_are_read_only_and_do_not_invoke_scanners(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "network-candidates.db"
    initialize_database(db_path)
    network = create_network(
        cidr="192.168.20.0/24",
        name="Saved LAN",
        description="Existing authorized network",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )
    monkeypatch.setattr(api_main, "DB_PATH", db_path)
    discovery = Mock(return_value=[make_candidate()])
    scanner = Mock(side_effect=AssertionError("network candidate route scanned"))
    monkeypatch.setattr(api_main, "discover_local_networks", discovery)
    monkeypatch.setattr(api_main, "NmapHostDiscoveryScanner", scanner)
    before_counts = table_row_counts(db_path)
    before_networks = list_networks(db_path=db_path)

    response = make_local_test_client(api_main.app).get("/network-candidates")

    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["cidr"] == "192.168.0.0/24"
    assert payload[0]["interface"] == "wlan0"
    assert payload[0]["source"] == "connected_route+interface_address"
    assert payload[0]["state"] == "CANDIDATE_NOT_AUTHORIZED"
    assert discovery.call_count == 1
    scanner.assert_not_called()
    assert table_row_counts(db_path) == before_counts
    assert list_networks(db_path=db_path) == before_networks
    assert before_networks[0]["id"] == network["id"]


def test_network_candidates_maps_local_state_failure_to_service_unavailable(
    monkeypatch,
):
    monkeypatch.setattr(
        api_main,
        "discover_local_networks",
        Mock(side_effect=LocalNetworkDiscoveryError("private detail")),
    )

    response = make_local_test_client(api_main.app).get("/network-candidates")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Local network candidates are unavailable."
    }
