import sqlite3

from database.db import initialize_database, save_event
from database.inventory import (
    create_device,
    find_device_by_stable_key,
    get_device,
    list_devices,
    list_observations,
    mark_devices_offline,
    save_observation,
    update_device_state,
)
from database.networks import create_network


def create_test_network(db_path):
    return create_network(
        cidr="192.168.1.0/24",
        name="Test LAN",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )


def create_test_device(db_path, network_id):
    return create_device(
        stable_key="network:1:mac:aa:bb:cc:dd:ee:ff",
        network_id=network_id,
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="router",
        vendor="Vendor",
        first_seen="2026-10-11T12:00:00",
        last_seen="2026-10-11T12:00:00",
        last_ip_address="192.168.1.1",
        status="ONLINE",
        identity_confidence="HIGH",
        db_path=db_path,
    )


def test_inventory_migration_is_idempotent_and_tables_exist(tmp_path):
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
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()

    assert {"events", "networks", "devices", "device_observations"} <= tables
    assert versions == [
        (1,),
        (2,),
        (3,),
        (4,),
        (5,),
        (6,),
        (7,),
        (8,),
        (9,),
        (10,),
        (11,),
        (12,),
        (13,),
        (14,),
        (15,),
        (16,),
        (17,),
        (18,),
        (19,),
        (20,),
        (21,),
        (22,),
        (23,),
        (24,),
        (25,),
        (26,),
        (27,),
    ]


def test_inventory_indexes_exist(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }

    assert "idx_devices_network_id" in indexes
    assert "idx_devices_mac_address" in indexes
    assert "idx_devices_last_ip_address" in indexes
    assert "idx_devices_last_seen" in indexes
    assert "idx_device_observations_device_observed" in indexes
    assert "idx_device_observations_network_ip_observed" in indexes


def test_device_and_observation_crud(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    device = create_test_device(db_path, network["id"])

    assert get_device(device["id"], db_path) == device
    assert find_device_by_stable_key(device["stable_key"], db_path) == device
    assert list_devices(network["id"], db_path) == [device]

    updated = update_device_state(
        device["id"],
        last_seen="2026-10-11T12:05:00",
        last_ip_address="192.168.1.20",
        status="ONLINE",
        mac_address=None,
        hostname=None,
        vendor=None,
        db_path=db_path,
    )
    assert updated["last_ip_address"] == "192.168.1.20"
    assert updated["vendor"] == "Vendor"

    observation = save_observation(
        device_id=device["id"],
        network_id=network["id"],
        ip_address="192.168.1.20",
        mac_address=None,
        hostname=None,
        vendor=None,
        status="ONLINE",
        observed_at="2026-10-11T12:05:00",
        source="mock",
        db_path=db_path,
    )
    assert list_observations(device["id"], db_path) == [observation]


def test_mark_devices_offline_preserves_records(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    device = create_test_device(db_path, network["id"])

    mark_devices_offline(
        network["id"],
        observed_device_ids=set(),
        observed_at="2026-10-11T12:10:00",
        db_path=db_path,
    )

    current = get_device(device["id"], db_path)
    assert current["status"] == "OFFLINE"
    assert get_device(device["id"], db_path) is not None


def test_existing_events_table_remains_usable(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    save_event(
        timestamp="2026-10-11T12:00:00",
        source_ip="192.168.1.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity="INFO",
        message="SSH pre-auth activity",
        event_count=1,
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
