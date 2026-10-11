from datetime import datetime, timedelta

import pytest

from database.inventory import get_device, list_devices, list_observations
from database.networks import create_network
from services.device_inventory import (
    DeviceInventoryError,
    DeviceInventoryService,
)
from services.host_discovery import discover_hosts
from services.scan_models import HostDiscoveryResult, ScanResult


START = datetime(2026, 10, 11, 12, 0, 0)


def create_test_network(db_path):
    return create_network(
        cidr="192.168.1.0/24",
        name="Test LAN",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )


def make_host(
    ip,
    at,
    mac="aa:bb:cc:dd:ee:ff",
    hostname="router",
    vendor="Vendor",
):
    return HostDiscoveryResult(
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        vendor=vendor,
        discovered_at=at,
        source="mock",
    )


def make_scan(hosts, completed_at=None, errors=()):
    completed_at = completed_at or START
    return ScanResult(
        target_network="192.168.1.0/24",
        scanner="mock",
        started_at=START,
        completed_at=completed_at,
        hosts=tuple(hosts),
        errors=tuple(errors),
    )


def test_first_observation_creates_device_and_history(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)

    devices = service.process_scan(
        network,
        make_scan([make_host("192.168.1.20", START)]),
    )

    assert len(devices) == 1
    device = get_device(devices[0]["id"], db_path)
    observations = list_observations(device["id"], db_path)
    assert device["first_seen"] == "2026-10-11T12:00:00"
    assert device["last_seen"] == "2026-10-11T12:00:00"
    assert device["last_ip_address"] == "192.168.1.20"
    assert device["status"] == "ONLINE"
    assert device["identity_confidence"] == "HIGH"
    assert len(observations) == 1


def test_same_mac_new_ip_updates_device_and_appends_history(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)
    first = make_host("192.168.1.20", START)
    second_time = START + timedelta(minutes=5)
    second = make_host(
        "192.168.1.30",
        second_time,
        hostname="new-router",
    )

    first_devices = service.process_scan(network, make_scan([first]))
    second_devices = service.process_scan(
        network,
        make_scan([second], completed_at=second_time),
    )

    assert first_devices[0]["id"] == second_devices[0]["id"]
    current = get_device(first_devices[0]["id"], db_path)
    assert current["first_seen"] == "2026-10-11T12:00:00"
    assert current["last_seen"] == "2026-10-11T12:05:00"
    assert current["last_ip_address"] == "192.168.1.30"
    assert current["hostname"] == "new-router"
    assert len(list_observations(current["id"], db_path)) == 2


def test_missing_new_evidence_does_not_erase_known_values(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)

    first = make_host("192.168.1.20", START)
    second_time = START + timedelta(minutes=5)
    second = make_host(
        "192.168.1.21",
        second_time,
        mac=None,
        hostname=None,
        vendor=None,
    )

    first_devices = service.process_scan(network, make_scan([first]))
    service.process_scan(network, make_scan([second], second_time))

    current = get_device(first_devices[0]["id"], db_path)
    assert current["vendor"] == "Vendor"
    assert current["hostname"] == "router"
    assert current["mac_address"] == "aa:bb:cc:dd:ee:ff"


def test_successful_scan_marks_missing_device_offline(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)

    first = service.process_scan(
        network,
        make_scan(
            [
                make_host("192.168.1.20", START),
                make_host(
                    "192.168.1.21",
                    START,
                    mac="11:22:33:44:55:66",
                    hostname="workstation",
                ),
            ]
        ),
    )
    later = START + timedelta(minutes=5)
    service.process_scan(
        network,
        make_scan([make_host("192.168.1.20", later)], later),
    )

    current_devices = list_devices(network["id"], db_path)
    states = {device["id"]: device["status"] for device in current_devices}
    assert states[first[0]["id"]] == "ONLINE"
    assert states[first[1]["id"]] == "OFFLINE"
    assert get_device(first[1]["id"], db_path) is not None


def test_empty_successful_scan_marks_all_devices_offline(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)
    devices = service.process_scan(
        network,
        make_scan([make_host("192.168.1.20", START)]),
    )

    later = START + timedelta(minutes=5)
    service.process_scan(network, make_scan([], later),)

    assert get_device(devices[0]["id"], db_path)["status"] == "OFFLINE"


def test_failed_scan_does_not_mark_devices_offline(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)
    devices = service.process_scan(
        network,
        make_scan([make_host("192.168.1.20", START)]),
    )

    with pytest.raises(DeviceInventoryError):
        service.process_scan(
            network,
            make_scan(
                [],
                START + timedelta(minutes=5),
                errors=("scanner failed",),
            ),
        )

    assert get_device(devices[0]["id"], db_path)["status"] == "ONLINE"


def test_different_macs_at_same_ip_remain_separate(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    service = DeviceInventoryService(db_path)

    devices = service.process_scan(
        network,
        make_scan(
            [
                make_host("192.168.1.20", START),
                make_host(
                    "192.168.1.20",
                    START,
                    mac="11:22:33:44:55:66",
                    hostname="other",
                ),
            ]
        ),
    )

    assert len(devices) == 2
    assert len(list_devices(network["id"], db_path)) == 2


def test_host_discovery_service_composes_with_inventory_service(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_test_network(db_path)
    scan_result = make_scan([make_host("192.168.1.20", START)])

    class FakeScanner:
        def discover_hosts(self, network_cidr):
            assert network_cidr == "192.168.1.0/24"
            return scan_result

    normalized_result = discover_hosts(network, FakeScanner())
    devices = DeviceInventoryService(db_path).process_scan(
        network,
        normalized_result,
    )

    assert len(devices) == 1
    assert len(list_observations(devices[0]["id"], db_path)) == 1