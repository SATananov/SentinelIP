import sqlite3
from datetime import datetime, timedelta

from database.changes import (
    create_change,
    get_change,
    list_changes,
    list_changes_by_type,
    list_device_changes,
    list_network_changes,
)
from database.db import initialize_database
from database.inventory import create_device
from database.networks import create_network
from services.change_models import ChangeRecord


def make_change(
    at,
    change_type="NEW_DEVICE",
    device_id=1,
    network_id=1,
    previous_value=None,
    current_value=None,
):
    return ChangeRecord(
        change_type=change_type,
        device_id=device_id,
        network_id=network_id,
        observed_at=at,
        source="test",
        confidence="HIGH",
        evidence_type="DEVICE_OBSERVATION",
        previous_value=previous_value,
        current_value=current_value or {"ip": "192.168.1.20"},
        message="A factual test change.",
        metadata_json={"test": True},
    )


def test_changes_migration_is_idempotent_and_indexed(tmp_path):
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
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }

    assert "changes" in tables
    assert "idx_changes_device_observed" in indexes
    assert "idx_changes_network_observed" in indexes
    assert "idx_changes_type_observed" in indexes
    assert "idx_changes_port" in indexes
    assert "idx_changes_service" in indexes


def test_change_crud_and_filters_are_stable(tmp_path):
    db_path = tmp_path / "test.db"
    create_network(
        "192.168.1.0/24",
        "Test LAN",
        "",
        True,
        True,
        db_path,
    )
    create_device(
        "network:1:mac:aa:bb:cc:dd:ee:ff",
        1,
        "aa:bb:cc:dd:ee:ff",
        "server",
        "Vendor",
        "2026-10-11T11:59:00",
        "2026-10-11T11:59:00",
        "192.168.1.20",
        "ONLINE",
        "HIGH",
        db_path,
    )
    first = create_change(
        make_change(datetime(2026, 10, 11, 12, 0, 0)),
        db_path,
    )
    second = create_change(
        make_change(
            datetime(2026, 10, 11, 12, 1, 0),
            change_type="IP_CHANGED",
        ),
        db_path,
    )

    assert get_change(first["id"], db_path)["metadata"] == {"test": True}
    assert [item["id"] for item in list_changes(db_path=db_path)] == [
        first["id"],
        second["id"],
    ]
    assert len(list_device_changes(1, db_path)) == 2
    assert len(list_network_changes(1, db_path)) == 2
    assert len(list_changes_by_type("IP_CHANGED", db_path)) == 1


def test_previous_and_current_values_are_preserved(tmp_path):
    db_path = tmp_path / "test.db"
    create_network(
        "192.168.1.0/24",
        "Test LAN",
        "",
        True,
        True,
        db_path,
    )
    create_device(
        "network:1:mac:aa:bb:cc:dd:ee:ff",
        1,
        "aa:bb:cc:dd:ee:ff",
        "server",
        "Vendor",
        "2026-10-11T11:59:00",
        "2026-10-11T11:59:00",
        "192.168.1.20",
        "ONLINE",
        "HIGH",
        db_path,
    )
    change = create_change(
        make_change(
            datetime(2026, 10, 11, 12, 0, 0),
            previous_value="192.168.1.20",
            current_value="192.168.1.21",
        ),
        db_path,
    )

    assert change["previous_value"] == "192.168.1.20"
    assert change["current_value"] == "192.168.1.21"