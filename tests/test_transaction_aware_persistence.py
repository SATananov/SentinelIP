import sqlite3
from datetime import datetime

import pytest

from database import changes as changes_db
from database import db as database_db
from database import inventory as inventory_db
from database import services as services_db
from database.db import get_connection, initialize_database
from database.networks import create_network
from services.change_detection import persist_changes
from services.change_models import ChangeRecord


def _setup(db_path):
    network = create_network(
        cidr="192.168.1.0/24", name="Test LAN", description="",
        authorized=True, enabled=True, db_path=db_path,
    )
    device = inventory_db.create_device(
        stable_key="network:1:mac:aa:bb:cc:dd:ee:ff", network_id=network["id"],
        mac_address="aa:bb:cc:dd:ee:ff", hostname="server", vendor="Vendor",
        first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00",
        last_ip_address="192.168.1.20", status="ONLINE", identity_confidence="HIGH",
        db_path=db_path,
    )
    return network, device


def _change(network_id, device_id, *, port_id=None, service_id=None, minute=0):
    return ChangeRecord(
        change_type="NEW_DEVICE", device_id=device_id, network_id=network_id,
        port_id=port_id, service_id=service_id,
        observed_at=datetime(2026, 10, 11, 12, minute), source="test",
        confidence="HIGH", evidence_type="DEVICE_OBSERVATION",
        message="A factual test change.", current_value={"ip": "192.168.1.20"},
    )


def _shared_connection(db_path):
    connection = get_connection(db_path)
    connection.row_factory = sqlite3.Row
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    return connection


def test_device_and_change_helpers_share_caller_transaction(tmp_path, monkeypatch):
    db_path = tmp_path / "transaction.db"
    initialize_database(db_path)
    network = create_network(
        cidr="192.168.1.0/24", name="Test LAN", description="",
        authorized=True, enabled=True, db_path=db_path,
    )
    connection = _shared_connection(db_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("caller-owned helper path opened or initialized another connection")

    monkeypatch.setattr(database_db, "initialize_database", forbidden)
    monkeypatch.setattr(database_db, "get_connection", forbidden)
    try:
        connection.execute("BEGIN IMMEDIATE")
        device = inventory_db.create_device(
            stable_key="network:1:mac:00:11:22:33:44:55", network_id=network["id"],
            mac_address="00:11:22:33:44:55", hostname="new-host", vendor=None,
            first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00",
            last_ip_address="192.168.1.21", status="ONLINE", identity_confidence="HIGH",
            db_path=db_path, conn=connection,
        )
        assert inventory_db.find_device_by_stable_key(device["stable_key"], conn=connection) == device
        observation = inventory_db.save_observation(
            device_id=device["id"], network_id=network["id"], ip_address="192.168.1.21",
            mac_address=None, hostname="new-host", vendor=None, status="ONLINE",
            observed_at="2026-10-11T12:00:00", source="test", conn=connection,
        )
        assert observation["device_id"] == device["id"]
        persisted = persist_changes([_change(network["id"], device["id"])], conn=connection)
        assert len(persisted) == 1
        assert connection.execute("SELECT COUNT(*) FROM device_observations").fetchone()[0] == 1
        connection.rollback()

        # The helper neither committed nor closed the caller connection.
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()

    with get_connection(db_path) as check:
        assert check.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert check.execute("SELECT COUNT(*) FROM device_observations").fetchone()[0] == 0
        assert check.execute("SELECT COUNT(*) FROM changes").fetchone()[0] == 0


def test_shared_connection_commit_persists_device_observation_and_change(tmp_path):
    db_path = tmp_path / "shared-commit.db"
    initialize_database(db_path)
    network = create_network(
        cidr="192.168.1.0/24", name="Test LAN", description="",
        authorized=True, enabled=True, db_path=db_path,
    )
    connection = _shared_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        device = inventory_db.create_device(
            stable_key="network:1:mac:00:11:22:33:44:55", network_id=network["id"],
            mac_address="00:11:22:33:44:55", hostname="new-host", vendor=None,
            first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00",
            last_ip_address="192.168.1.21", status="ONLINE", identity_confidence="HIGH",
            conn=connection,
        )
        inventory_db.save_observation(
            device_id=device["id"], network_id=network["id"], ip_address="192.168.1.21",
            mac_address=None, hostname="new-host", vendor=None, status="ONLINE",
            observed_at="2026-10-11T12:00:00", source="test", conn=connection,
        )
        persist_changes([_change(network["id"], device["id"])], conn=connection)
        connection.commit()
    finally:
        connection.close()

    with get_connection(db_path) as check:
        assert check.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM device_observations").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM changes").fetchone()[0] == 1


def test_device_update_observation_and_change_rollback_together(tmp_path):
    db_path = tmp_path / "device-rollback.db"
    network, device = _setup(db_path)
    connection = _shared_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        inventory_db.update_device_state(
            device["id"], last_seen="2026-10-11T12:05:00", last_ip_address="192.168.1.22",
            status="ONLINE", mac_address=None, hostname=None, vendor=None,
            db_path=db_path, conn=connection,
        )
        inventory_db.save_observation(
            device_id=device["id"], network_id=network["id"], ip_address="192.168.1.22",
            mac_address=None, hostname=None, vendor=None, status="ONLINE",
            observed_at="2026-10-11T12:05:00", source="test", conn=connection,
        )
        persist_changes([_change(network["id"], device["id"])], conn=connection)
        inventory_db.mark_devices_offline(
            network["id"], observed_device_ids=set(), observed_at="2026-10-11T12:06:00",
            db_path=db_path, conn=connection,
        )
        connection.rollback()
    finally:
        connection.close()

    with get_connection(db_path) as check:
        row = check.execute("SELECT last_ip_address FROM devices WHERE id=?", (device["id"],)).fetchone()
        assert row[0] == "192.168.1.20"
        assert check.execute("SELECT status FROM devices WHERE id=?", (device["id"],)).fetchone()[0] == "ONLINE"
        assert check.execute("SELECT COUNT(*) FROM device_observations").fetchone()[0] == 0
        assert check.execute("SELECT COUNT(*) FROM changes").fetchone()[0] == 0


def test_port_service_observation_and_change_helpers_share_rollback(tmp_path, monkeypatch):
    db_path = tmp_path / "service-rollback.db"
    network, device = _setup(db_path)
    connection = _shared_connection(db_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("caller-owned helper path opened or initialized another connection")

    monkeypatch.setattr(database_db, "initialize_database", forbidden)
    monkeypatch.setattr(database_db, "get_connection", forbidden)
    try:
        connection.execute("BEGIN IMMEDIATE")
        port = services_db.create_port(
            device_id=device["id"], port_number=22, transport="tcp", state="open",
            first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00",
            conn=connection,
        )
        assert services_db.find_port(device["id"], 22, "tcp", conn=connection) == port
        services_db.update_port(port["id"], "2026-10-11T12:05:00", "open", conn=connection)
        services_db.save_port_observation(
            device_id=device["id"], port_id=port["id"], ip_address="192.168.1.20",
            port_number=22, transport="tcp", state="open", observed_at="2026-10-11T12:05:00",
            source="test", conn=connection,
        )
        service = services_db.create_service(
            device_id=device["id"], port_id=port["id"], service_name="ssh",
            product="OpenSSH", version="9.6", extra_info=None, confidence="HIGH",
            first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00",
            conn=connection,
        )
        assert services_db.find_service_by_port(port["id"], conn=connection) == service
        services_db.update_service(
            service["id"], "ssh", "OpenSSH", "9.7", None, "HIGH",
            "2026-10-11T12:05:00", conn=connection,
        )
        services_db.save_service_observation(
            service_id=service["id"], device_id=device["id"], port_id=port["id"],
            service_name="ssh", product="OpenSSH", version="9.7", extra_info=None,
            confidence="HIGH", observed_at="2026-10-11T12:05:00", source="test",
            conn=connection,
        )
        persist_changes(
            [_change(network["id"], device["id"], port_id=port["id"], service_id=service["id"])],
            conn=connection,
        )
        connection.rollback()
    finally:
        connection.close()

    with get_connection(db_path) as check:
        for table in ("ports", "port_observations", "services", "service_observations", "changes"):
            assert check.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_existing_port_and_service_updates_rollback(tmp_path):
    db_path = tmp_path / "existing-service-rollback.db"
    network, device = _setup(db_path)
    port = services_db.create_port(
        device_id=device["id"], port_number=22, transport="tcp", state="open",
        first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00", db_path=db_path,
    )
    service = services_db.create_service(
        device_id=device["id"], port_id=port["id"], service_name="ssh",
        product="OpenSSH", version="9.6", extra_info=None, confidence="HIGH",
        first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00", db_path=db_path,
    )
    connection = _shared_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        services_db.update_port(port["id"], "2026-10-11T12:05:00", "closed", conn=connection)
        services_db.update_service(
            service["id"], "ssh", "OpenSSH", "9.7", None, "HIGH",
            "2026-10-11T12:05:00", conn=connection,
        )
        connection.rollback()
    finally:
        connection.close()

    with get_connection(db_path) as check:
        restored_port = check.execute(
            "SELECT state,last_seen FROM ports WHERE id=?", (port["id"],)
        ).fetchone()
        restored_service = check.execute(
            "SELECT version,last_seen FROM services WHERE id=?", (service["id"],)
        ).fetchone()
        assert tuple(restored_port) == ("open", "2026-10-11T12:00:00")
        assert tuple(restored_service) == ("9.6", "2026-10-11T12:00:00")


def test_inventory_write_rolls_back_when_service_helper_fails(tmp_path):
    db_path = tmp_path / "cross-module-rollback.db"
    _, existing_device = _setup(db_path)
    services_db.create_port(
        device_id=existing_device["id"], port_number=22, transport="tcp", state="open",
        first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00", db_path=db_path,
    )
    connection = _shared_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        inventory_db.create_device(
            stable_key="network:1:mac:00:11:22:33:44:55", network_id=existing_device["network_id"],
            mac_address="00:11:22:33:44:55", hostname="new-host", vendor=None,
            first_seen="2026-10-11T12:00:00", last_seen="2026-10-11T12:00:00",
            last_ip_address="192.168.1.21", status="ONLINE", identity_confidence="HIGH",
            conn=connection,
        )
        with pytest.raises(sqlite3.IntegrityError):
            services_db.create_port(
                device_id=existing_device["id"], port_number=22, transport="tcp", state="open",
                first_seen="2026-10-11T12:05:00", last_seen="2026-10-11T12:05:00",
                conn=connection,
            )
        connection.rollback()
    finally:
        connection.close()

    with get_connection(db_path) as check:
        assert check.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM ports").fetchone()[0] == 1


def test_change_batch_error_leaves_rollback_to_caller(tmp_path, monkeypatch):
    db_path = tmp_path / "change-batch.db"
    network, device = _setup(db_path)
    connection = _shared_connection(db_path)
    real_create_change = changes_db.create_change
    calls = 0

    def fail_second(record, db_path_arg=database_db.DB_PATH, conn=None):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sqlite3.IntegrityError("injected second-row failure")
        return real_create_change(record, db_path_arg, conn=conn)

    monkeypatch.setattr(changes_db, "create_change", fail_second)
    try:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.IntegrityError):
            persist_changes(
                [_change(network["id"], device["id"], minute=0),
                 _change(network["id"], device["id"], minute=1)],
                conn=connection,
            )
        connection.rollback()
    finally:
        connection.close()

    with get_connection(db_path) as check:
        assert check.execute("SELECT COUNT(*) FROM changes").fetchone()[0] == 0
