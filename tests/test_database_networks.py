import sqlite3

import pytest

from database.db import initialize_database, save_event
from database.networks import (
    create_network,
    delete_network,
    get_network,
    list_networks,
    update_network,
)


def test_migration_is_idempotent(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations"
        ).fetchall()

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
        (28,),
        (29,),
        (30,),
        (31,),
        (32,),
        (33,),
        (34,),
        (35,),
        (36,),
    ]


def test_networks_table_exists(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'networks'
            """
        ).fetchone()

    assert row == ("networks",)


def test_existing_events_table_remains_usable(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)
    save_event(
        timestamp="2026-10-11T08:34:35",
        source_ip="192.168.122.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity="INFO",
        message="SSH pre-auth activity",
        event_count=1,
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    assert count == 1


def test_network_crud(tmp_path):
    db_path = tmp_path / "test.db"

    created = create_network(
        cidr="192.168.1.1/25",
        name="Home LAN",
        description="Authorized home network",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )

    assert created["cidr"] == "192.168.1.0/25"
    assert created["authorized"] is True
    assert created["enabled"] is True
    assert list_networks(db_path) == [created]
    assert get_network(created["id"], db_path) == created

    updated = update_network(
        created["id"],
        name="Updated LAN",
        description="Updated description",
        enabled=False,
        db_path=db_path,
    )

    assert updated["name"] == "Updated LAN"
    assert updated["description"] == "Updated description"
    assert updated["enabled"] is False
    assert delete_network(created["id"], db_path) is True
    assert get_network(created["id"], db_path) is None
    assert delete_network(created["id"], db_path) is False


def test_duplicate_cidr_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    values = {
        "cidr": "192.168.0.0/24",
        "name": "LAN",
        "description": "",
        "authorized": True,
        "enabled": True,
        "db_path": db_path,
    }

    create_network(**values)

    with pytest.raises(sqlite3.IntegrityError):
        create_network(**values)


def test_network_authorization_is_required(tmp_path):
    with pytest.raises(ValueError):
        create_network(
            cidr="192.168.0.0/24",
            name="LAN",
            description="",
            authorized=False,
            enabled=True,
            db_path=tmp_path / "test.db",
        )
