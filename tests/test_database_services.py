import sqlite3

import pytest

from database.db import initialize_database
from database.networks import create_network
from database.inventory import create_device
from database.services import (
    create_port,
    create_service,
    find_port,
    find_service_by_port,
    list_port_observations,
    list_service_observations,
    list_services,
    save_port_observation,
    save_service_observation,
    update_port,
    update_service,
)


def setup_device(db_path):
    network = create_network(
        cidr="192.168.1.0/24",
        name="Test LAN",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )
    device = create_device(
        stable_key="network:1:mac:aa:bb:cc:dd:ee:ff",
        network_id=network["id"],
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="server",
        vendor="Vendor",
        first_seen="2026-10-11T12:00:00",
        last_seen="2026-10-11T12:00:00",
        last_ip_address="192.168.1.20",
        status="ONLINE",
        identity_confidence="HIGH",
        db_path=db_path,
    )
    return network, device


def test_service_migration_is_idempotent_and_tables_exist(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {
        "ports",
        "port_observations",
        "services",
        "service_observations",
    } <= tables


def test_port_service_and_observation_persistence(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_device(db_path)
    port = create_port(
        device_id=device["id"],
        port_number=22,
        transport="tcp",
        state="open",
        first_seen="2026-10-11T12:00:00",
        last_seen="2026-10-11T12:00:00",
        db_path=db_path,
    )
    assert find_port(device["id"], 22, "tcp", db_path)["id"] == port["id"]

    save_port_observation(
        device_id=device["id"],
        port_id=port["id"],
        ip_address="192.168.1.20",
        port_number=22,
        transport="tcp",
        state="open",
        observed_at="2026-10-11T12:00:00",
        source="mock",
        db_path=db_path,
    )
    assert len(list_port_observations(port["id"], db_path)) == 1

    service = create_service(
        device_id=device["id"],
        port_id=port["id"],
        service_name="ssh",
        product="OpenSSH",
        version="9.6p1",
        extra_info=None,
        confidence="HIGH",
        first_seen="2026-10-11T12:00:00",
        last_seen="2026-10-11T12:00:00",
        db_path=db_path,
    )
    assert find_service_by_port(port["id"], db_path)["id"] == service["id"]
    assert list_services(device["id"], db_path) == [service]

    update_port(port["id"], "2026-10-11T12:05:00", "open", db_path)
    update_service(
        service["id"],
        "ssh",
        None,
        None,
        None,
        "MEDIUM",
        "2026-10-11T12:05:00",
        db_path,
    )
    save_service_observation(
        service_id=service["id"],
        device_id=device["id"],
        port_id=port["id"],
        service_name="ssh",
        product=None,
        version=None,
        extra_info=None,
        confidence="MEDIUM",
        observed_at="2026-10-11T12:05:00",
        source="mock",
        db_path=db_path,
    )
    assert len(list_service_observations(service["id"], db_path)) == 1


def test_duplicate_current_port_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    _, device = setup_device(db_path)
    values = {
        "device_id": device["id"],
        "port_number": 22,
        "transport": "tcp",
        "state": "open",
        "first_seen": "2026-10-11T12:00:00",
        "last_seen": "2026-10-11T12:00:00",
        "db_path": db_path,
    }
    create_port(**values)

    with pytest.raises(sqlite3.IntegrityError):
        create_port(**values)