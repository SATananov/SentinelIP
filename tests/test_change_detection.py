from datetime import datetime

from database.changes import list_changes
from database.inventory import get_device, list_observations
from database.networks import create_network
from database.services import list_port_observations, list_service_observations
from services.change_detection import (
    device_disappearance_change,
    device_observation_changes,
    port_observation_changes,
    service_observation_changes,
)
from services.change_models import ChangeType
from services.device_inventory import DeviceInventoryService
from services.scan_models import HostDiscoveryResult, ScanResult
from services.service_inventory import ServiceInventoryService
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)


OBSERVED_AT = datetime(2026, 10, 11, 12, 0, 0)


def device(status="ONLINE", ip="192.168.1.20"):
    return {
        "id": 1,
        "network_id": 2,
        "stable_key": "network:2:mac:aa:bb:cc:dd:ee:ff",
        "identity_confidence": "HIGH",
        "status": status,
        "last_ip_address": ip,
    }


def port_record(state="OPEN"):
    return {
        "id": 4,
        "device_id": 1,
        "port_number": 22,
        "transport": "tcp",
        "state": state,
    }


def service_record(version="9.6p1", name="ssh", product="OpenSSH"):
    return {
        "id": 5,
        "device_id": 1,
        "port_id": 4,
        "service_name": name,
        "product": product,
        "version": version,
        "confidence": "HIGH",
    }


def test_device_transitions_and_ip_change():
    new = device()
    assert device_observation_changes(None, new, 2, OBSERVED_AT)[0].change_type == (
        ChangeType.NEW_DEVICE
    )
    assert device_observation_changes(
        device(status="OFFLINE"),
        new,
        2,
        OBSERVED_AT,
    )[0].change_type == ChangeType.DEVICE_REAPPEARED
    assert device_observation_changes(
        device(),
        device(ip="192.168.1.21"),
        2,
        OBSERVED_AT,
    )[0].change_type == ChangeType.IP_CHANGED


def test_disappearance_is_factual():
    change = device_disappearance_change(device(), 2, OBSERVED_AT)

    assert change.change_type == ChangeType.DEVICE_DISAPPEARED
    assert "not observed" in change.message
    assert "compromised" not in change.message.lower()


def test_port_changes_do_not_infer_closed_from_absence():
    assert port_observation_changes(None, port_record(), 2, OBSERVED_AT)[0].change_type == (
        ChangeType.NEW_PORT
    )
    assert port_observation_changes(
        port_record(),
        port_record(),
        2,
        OBSERVED_AT,
    ) == []
    assert port_observation_changes(
        port_record("CLOSED"),
        port_record("OPEN"),
        2,
        OBSERVED_AT,
    )[0].change_type == ChangeType.PORT_REOPENED


def test_service_transitions_are_evidence_based():
    assert service_observation_changes(
        None,
        service_record(),
        2,
        OBSERVED_AT,
    )[0].change_type == ChangeType.SERVICE_IDENTIFIED
    assert service_observation_changes(
        service_record(),
        service_record(version="9.7"),
        2,
        OBSERVED_AT,
    )[0].change_type == ChangeType.SERVICE_VERSION_CHANGED
    assert service_observation_changes(
        service_record(),
        service_record(name="http", product="nginx"),
        2,
        OBSERVED_AT,
    )[0].change_type == ChangeType.SERVICE_CHANGED
    assert service_observation_changes(
        service_record(),
        service_record(version=None),
        2,
        OBSERVED_AT,
    ) == []


def test_mocked_end_to_end_change_history_preserves_raw_observations(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_network(
        "192.168.1.0/24",
        "Test LAN",
        "",
        True,
        True,
        db_path,
    )
    device_inventory = DeviceInventoryService(db_path)
    service_inventory = ServiceInventoryService(db_path)

    def host_scan(at, hosts):
        return ScanResult(
            target_network="192.168.1.0/24",
            scanner="mock-host",
            started_at=at,
            completed_at=at,
            hosts=tuple(hosts),
        )

    def host(at):
        return HostDiscoveryResult(
            ip_address="192.168.1.20",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="server",
            vendor="Vendor",
            discovered_at=at,
            source="mock-host",
        )

    def service_scan(at, version):
        return ServiceDiscoveryResult(
            target_ip="192.168.1.20",
            scanner="mock-service",
            started_at=at,
            completed_at=at,
            ports=(
                PortObservation(
                    ip_address="192.168.1.20",
                    port=22,
                    transport="tcp",
                    state="open",
                    observed_at=at,
                    source="mock-service",
                ),
            ),
            services=(
                ServiceObservation(
                    ip_address="192.168.1.20",
                    port=22,
                    transport="tcp",
                    service_name="ssh",
                    product="OpenSSH",
                    version=version,
                    extra_info=None,
                    confidence="HIGH",
                    observed_at=at,
                    source="mock-service",
                ),
            ),
        )

    first_time = datetime(2026, 10, 11, 12, 0, 0)
    devices = device_inventory.process_scan(
        network,
        host_scan(first_time, [host(first_time)]),
    )
    device = get_device(devices[0]["id"], db_path)

    service_inventory.process_result(
        network,
        device,
        service_scan(datetime(2026, 10, 11, 12, 1, 0), "9.6p1"),
    )
    service_inventory.process_result(
        network,
        device,
        service_scan(datetime(2026, 10, 11, 12, 2, 0), "9.7"),
    )

    device_inventory.process_scan(
        network,
        host_scan(datetime(2026, 10, 11, 12, 3, 0), []),
    )
    device_inventory.process_scan(
        network,
        host_scan(datetime(2026, 10, 11, 12, 4, 0), [host(datetime(2026, 10, 11, 12, 4, 0))]),
    )

    changes = list_changes(db_path=db_path)
    assert [change["change_type"] for change in changes] == [
        "NEW_DEVICE",
        "NEW_PORT",
        "SERVICE_IDENTIFIED",
        "SERVICE_VERSION_CHANGED",
        "DEVICE_DISAPPEARED",
        "DEVICE_REAPPEARED",
    ]

    assert len(list_observations(device["id"], db_path)) == 2
    port_id = service_inventory.process_result(
        network,
        device,
        service_scan(datetime(2026, 10, 11, 12, 5, 0), "9.7"),
    )["ports"][0]["id"]
    service_id = service_inventory.process_result(
        network,
        device,
        service_scan(datetime(2026, 10, 11, 12, 6, 0), "9.7"),
    )["services"][0]["id"]
    assert len(list_port_observations(port_id, db_path)) == 4
    assert len(list_service_observations(service_id, db_path)) == 4