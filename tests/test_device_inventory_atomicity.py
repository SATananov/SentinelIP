import sqlite3
from datetime import datetime, timedelta

import pytest

from database import inventory as inventory_db
from database.db import get_connection
from database.networks import create_network
from services import device_inventory as device_inventory_module
from services.device_inventory import DeviceInventoryError, DeviceInventoryService
from services.scan_models import HostDiscoveryResult, ScanResult

START = datetime(2026, 10, 11, 12, 0, 0)


def make_host(ip, at, *, mac="aa:bb:cc:dd:ee:ff", hostname="router", vendor="Vendor"):
    return HostDiscoveryResult(
        ip_address=ip, mac_address=mac, hostname=hostname, vendor=vendor,
        discovered_at=at, source="mock",
    )


def make_scan(hosts, completed_at=None, errors=()):
    completed_at = completed_at or START
    return ScanResult(
        target_network="192.168.1.0/24", scanner="mock", started_at=START,
        completed_at=completed_at, hosts=tuple(hosts), errors=tuple(errors),
    )


def _network(db_path):
    return create_network(
        cidr="192.168.1.0/24", name="Test LAN", description="",
        authorized=True, enabled=True, db_path=db_path,
    )


def _counts(db_path):
    with get_connection(db_path) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("devices", "device_observations", "changes")
        }


def _device(db_path, device_id):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return dict(connection.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone())


@pytest.mark.parametrize("failure_point", ["device_insert", "change_insert", "observation"])
def test_new_device_failure_rolls_back_all_effects(tmp_path, monkeypatch, failure_point):
    db_path = tmp_path / f"new-{failure_point}.db"
    network = _network(db_path)
    real_create = inventory_db.create_device
    real_changes = device_inventory_module.persist_changes

    if failure_point == "device_insert":
        def fail_after_device(*args, **kwargs):
            real_create(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after device insert")
        monkeypatch.setattr(inventory_db, "create_device", fail_after_device)
    elif failure_point == "change_insert":
        def fail_after_change(*args, **kwargs):
            real_changes(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after change insert")
        monkeypatch.setattr(device_inventory_module, "persist_changes", fail_after_change)
    else:
        def fail_before_observation(*_args, **_kwargs):
            raise sqlite3.IntegrityError("injected before observation")
        monkeypatch.setattr(inventory_db, "save_observation", fail_before_observation)

    with pytest.raises(sqlite3.IntegrityError):
        DeviceInventoryService(db_path).process_scan(
            network, make_scan([make_host("192.168.1.20", START)])
        )

    assert _counts(db_path) == {"devices": 0, "device_observations": 0, "changes": 0}


@pytest.mark.parametrize("failure_point", ["transition_change", "device_update", "observation"])
def test_existing_device_failure_restores_state_and_history(tmp_path, monkeypatch, failure_point):
    db_path = tmp_path / f"existing-{failure_point}.db"
    network = _network(db_path)
    service = DeviceInventoryService(db_path)
    original = service.process_scan(network, make_scan([make_host("192.168.1.20", START)]))[0]
    original_counts = _counts(db_path)
    second_time = START + timedelta(minutes=5)
    real_changes = device_inventory_module.persist_changes
    real_update = inventory_db.update_device_state

    if failure_point == "transition_change":
        def fail_after_change(*args, **kwargs):
            real_changes(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after transition change")
        monkeypatch.setattr(device_inventory_module, "persist_changes", fail_after_change)
    elif failure_point == "device_update":
        def fail_after_update(*args, **kwargs):
            real_update(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after device update")
        monkeypatch.setattr(inventory_db, "update_device_state", fail_after_update)
    else:
        def fail_before_observation(*_args, **_kwargs):
            raise sqlite3.IntegrityError("injected before observation")
        monkeypatch.setattr(inventory_db, "save_observation", fail_before_observation)

    changed_host = make_host("192.168.1.21", second_time)
    with pytest.raises(sqlite3.IntegrityError):
        service.process_scan(network, make_scan([changed_host], second_time))

    assert _device(db_path, original["id"])["last_ip_address"] == "192.168.1.20"
    assert _device(db_path, original["id"])["last_seen"] == "2026-10-11T12:00:00"
    assert _counts(db_path) == original_counts


def test_later_host_failure_rolls_back_earlier_hosts(tmp_path, monkeypatch):
    db_path = tmp_path / "multi-host.db"
    network = _network(db_path)
    real_save = inventory_db.save_observation
    saves = 0

    def fail_second_observation(*args, **kwargs):
        nonlocal saves
        saves += 1
        if saves == 2:
            raise sqlite3.IntegrityError("injected on second host")
        return real_save(*args, **kwargs)

    monkeypatch.setattr(inventory_db, "save_observation", fail_second_observation)
    hosts = [
        make_host("192.168.1.20", START, mac="00:00:00:00:00:01"),
        make_host("192.168.1.21", START, mac="00:00:00:00:00:02"),
    ]
    with pytest.raises(sqlite3.IntegrityError):
        DeviceInventoryService(db_path).process_scan(network, make_scan(hosts))
    assert _counts(db_path) == {"devices": 0, "device_observations": 0, "changes": 0}


def test_reconciliation_change_failure_rolls_back_scanned_host(tmp_path, monkeypatch):
    db_path = tmp_path / "reconcile-change.db"
    network = _network(db_path)
    service = DeviceInventoryService(db_path)
    omitted = service.process_scan(network, make_scan([make_host("192.168.1.20", START)]))[0]
    before = _counts(db_path)
    real_changes = device_inventory_module.persist_changes

    def fail_after_disappearance(records, *args, **kwargs):
        result = real_changes(records, *args, **kwargs)
        if records and records[0].change_type.value == "DEVICE_DISAPPEARED":
            raise sqlite3.IntegrityError("injected during reconciliation")
        return result

    monkeypatch.setattr(device_inventory_module, "persist_changes", fail_after_disappearance)
    with pytest.raises(sqlite3.IntegrityError):
        service.process_scan(
            network,
            make_scan([make_host("192.168.1.21", START + timedelta(minutes=5),
                                 mac="00:00:00:00:00:02")],
                      START + timedelta(minutes=5)),
        )

    assert _device(db_path, omitted["id"])["status"] == "ONLINE"
    assert _counts(db_path) == before


def test_offline_update_failure_rolls_back_hosts_and_disappearance(tmp_path, monkeypatch):
    db_path = tmp_path / "offline-update.db"
    network = _network(db_path)
    service = DeviceInventoryService(db_path)
    omitted = service.process_scan(network, make_scan([make_host("192.168.1.20", START)]))[0]
    before = _counts(db_path)
    real_mark = inventory_db.mark_devices_offline

    def fail_after_offline_update(*args, **kwargs):
        real_mark(*args, **kwargs)
        raise sqlite3.IntegrityError("injected after offline update")

    monkeypatch.setattr(inventory_db, "mark_devices_offline", fail_after_offline_update)
    with pytest.raises(sqlite3.IntegrityError):
        service.process_scan(
            network,
            make_scan([make_host("192.168.1.21", START + timedelta(minutes=5),
                                 mac="00:00:00:00:00:02")],
                      START + timedelta(minutes=5)),
        )

    assert _device(db_path, omitted["id"])["status"] == "ONLINE"
    assert _counts(db_path) == before


def test_successful_reconciliation_commits_seen_and_omitted_devices(tmp_path):
    db_path = tmp_path / "successful-reconcile.db"
    network = _network(db_path)
    service = DeviceInventoryService(db_path)
    initial = service.process_scan(network, make_scan([
        make_host("192.168.1.20", START, mac="00:00:00:00:00:01"),
        make_host("192.168.1.21", START, mac="00:00:00:00:00:02"),
    ]))
    seen, omitted = initial
    later = START + timedelta(minutes=5)

    result = service.process_scan(
        network,
        make_scan([make_host("192.168.1.20", later, mac="00:00:00:00:00:01")], later),
    )

    assert [item["id"] for item in result] == [seen["id"]]
    assert _device(db_path, seen["id"])["status"] == "ONLINE"
    assert _device(db_path, omitted["id"])["status"] == "OFFLINE"
    with get_connection(db_path) as connection:
        types = [row[0] for row in connection.execute(
            "SELECT change_type FROM changes ORDER BY id"
        )]
    assert types.count("DEVICE_DISAPPEARED") == 1


def test_no_change_scan_preserves_change_rows_and_appends_observation(tmp_path):
    db_path = tmp_path / "no-change.db"
    network = _network(db_path)
    service = DeviceInventoryService(db_path)
    device = service.process_scan(network, make_scan([make_host("192.168.1.20", START)]))[0]
    later = START + timedelta(minutes=5)

    service.process_scan(network, make_scan([make_host("192.168.1.20", later)], later))

    assert _counts(db_path) == {"devices": 1, "device_observations": 2, "changes": 1}
    assert _device(db_path, device["id"])["last_seen"] == "2026-10-11T12:05:00"


def test_supplied_connection_scan_can_be_rolled_back_by_caller(tmp_path, monkeypatch):
    db_path = tmp_path / "caller-owned.db"
    network = _network(db_path)
    connection = get_connection(db_path)
    connection.row_factory = sqlite3.Row
    real_init = device_inventory_module.initialize_database
    real_get = device_inventory_module.get_connection

    def forbidden(*_args, **_kwargs):
        pytest.fail("supplied-connection scan opened or initialized another connection")

    monkeypatch.setattr(device_inventory_module, "initialize_database", forbidden)
    monkeypatch.setattr(device_inventory_module, "get_connection", forbidden)
    try:
        connection.execute("BEGIN IMMEDIATE")
        result = DeviceInventoryService(db_path).process_scan(
            network, make_scan([make_host("192.168.1.20", START)]), conn=connection
        )
        assert inventory_db.list_devices(network["id"], conn=connection)[0]["id"] == result[0]["id"]
        connection.rollback()
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()
        monkeypatch.setattr(device_inventory_module, "initialize_database", real_init)
        monkeypatch.setattr(device_inventory_module, "get_connection", real_get)

    assert _counts(db_path) == {"devices": 0, "device_observations": 0, "changes": 0}


def test_standalone_large_scan_uses_one_connection_and_one_initialization(tmp_path, monkeypatch):
    db_path = tmp_path / "large-scan.db"
    network = _network(db_path)
    real_init = device_inventory_module.initialize_database
    real_get = device_inventory_module.get_connection
    init_calls = 0
    connection_calls = 0

    def count_init(path):
        nonlocal init_calls
        init_calls += 1
        return real_init(path)

    def count_get(path):
        nonlocal connection_calls
        connection_calls += 1
        return real_get(path)

    monkeypatch.setattr(device_inventory_module, "initialize_database", count_init)
    monkeypatch.setattr(device_inventory_module, "get_connection", count_get)
    hosts = [
        make_host(
            f"192.168.1.{index}", START,
            mac=f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
            hostname=f"host-{index}",
        )
        for index in range(1, 255)
    ]

    result = DeviceInventoryService(db_path).process_scan(network, make_scan(hosts))

    assert len(result) == 254
    assert init_calls == 1
    assert connection_calls == 1
    monkeypatch.setattr(device_inventory_module, "initialize_database", real_init)
    monkeypatch.setattr(device_inventory_module, "get_connection", real_get)
    assert _counts(db_path) == {"devices": 254, "device_observations": 254, "changes": 254}


def test_scan_revalidates_persisted_network_inside_transaction(tmp_path):
    db_path = tmp_path / "network-state.db"
    network = _network(db_path)
    with get_connection(db_path) as connection:
        connection.execute("UPDATE networks SET enabled=0 WHERE id=?", (network["id"],))

    with pytest.raises(DeviceInventoryError, match="Stored network"):
        DeviceInventoryService(db_path).process_scan(
            network, make_scan([make_host("192.168.1.20", START)])
        )
    assert _counts(db_path) == {"devices": 0, "device_observations": 0, "changes": 0}


def test_invalid_host_input_is_rejected_before_opening_transaction(tmp_path, monkeypatch):
    db_path = tmp_path / "invalid-host.db"
    network = _network(db_path)
    scan = ScanResult(
        target_network=network["cidr"], scanner="mock", started_at=START,
        completed_at=START, hosts=(object(),),
    )

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid host input reached database setup")

    monkeypatch.setattr(device_inventory_module, "initialize_database", forbidden)
    monkeypatch.setattr(device_inventory_module, "get_connection", forbidden)
    with pytest.raises(DeviceInventoryError, match="invalid host"):
        DeviceInventoryService(db_path).process_scan(network, scan)
