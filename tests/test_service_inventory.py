from datetime import datetime, timedelta

import pytest

from database.inventory import create_device
from database.networks import create_network
from database.services import (
    find_service_by_port,
    list_port_observations,
    list_ports,
    list_service_observations,
    list_services,
)
from services.service_inventory import ServiceInventoryError, ServiceInventoryService
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)


START = datetime(2026, 10, 11, 12, 0, 0)


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


def port(number, at=START):
    return PortObservation(
        ip_address="192.168.1.20",
        port=number,
        transport="tcp",
        state="open",
        observed_at=at,
        source="mocked-scanner",
    )


def service(
    number,
    at=START,
    service_name="ssh",
    product="OpenSSH",
    version="9.6p1",
):
    return ServiceObservation(
        ip_address="192.168.1.20",
        port=number,
        transport="tcp",
        service_name=service_name,
        product=product,
        version=version,
        extra_info=None,
        confidence="HIGH",
        observed_at=at,
        source="mocked-scanner",
    )


def result(ports, services=(), at=START, errors=()):
    return ServiceDiscoveryResult(
        target_ip="192.168.1.20",
        scanner="mocked-scanner",
        started_at=START,
        completed_at=at,
        ports=tuple(ports),
        services=tuple(services),
        errors=tuple(errors),
    )


def test_first_result_creates_ports_and_services(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_device(db_path)
    processed = ServiceInventoryService(db_path).process_result(
        network,
        device,
        result(
            ports=(port(22), port(80)),
            services=(
                service(22),
                service(
                    80,
                    service_name="http",
                    product="nginx",
                    version="1.24.0",
                ),
            ),
        ),
    )

    assert len(processed["ports"]) == 2
    assert len(processed["services"]) == 2
    assert len(list_ports(device["id"], db_path)) == 2
    assert len(list_services(device["id"], db_path)) == 2
    assert len(list_port_observations(processed["ports"][0]["id"], db_path)) == 1
    assert len(
        list_service_observations(processed["services"][0]["id"], db_path)
    ) == 1


def test_repeat_result_updates_current_records_and_appends_history(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_device(db_path)
    inventory = ServiceInventoryService(db_path)
    first = inventory.process_result(
        network,
        device,
        result((port(22),), (service(22),)),
    )
    later = START + timedelta(minutes=5)
    second = inventory.process_result(
        network,
        device,
        result(
            (port(22, later),),
            (service(22, later, product=None, version=None),),
            at=later,
        ),
    )

    assert first["ports"][0]["id"] == second["ports"][0]["id"]
    assert first["services"][0]["id"] == second["services"][0]["id"]
    assert len(list_ports(device["id"], db_path)) == 1
    assert len(list_services(device["id"], db_path)) == 1
    assert len(list_port_observations(first["ports"][0]["id"], db_path)) == 2
    assert len(list_service_observations(first["services"][0]["id"], db_path)) == 2

    current_service = find_service_by_port(first["ports"][0]["id"], db_path)
    assert current_service["product"] == "OpenSSH"
    assert current_service["version"] == "9.6p1"
    assert current_service["last_seen"] == "2026-10-11T12:05:00"


def test_open_port_without_service_evidence_stays_service_unknown(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_device(db_path)

    processed = ServiceInventoryService(db_path).process_result(
        network,
        device,
        result(
            ports=(port(443),),
            services=(service(443, service_name=None, product=None, version=None),),
        ),
    )

    assert len(processed["ports"]) == 1
    assert processed["services"] == []
    assert list_services(device["id"], db_path) == []


def test_failed_result_has_no_persistence_side_effects(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_device(db_path)

    with pytest.raises(ServiceInventoryError):
        ServiceInventoryService(db_path).process_result(
            network,
            device,
            result((port(22),), errors=("scanner failed",)),
        )

    assert list_ports(device["id"], db_path) == []
    assert list_services(device["id"], db_path) == []


def test_unauthorized_or_mismatched_context_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_device(db_path)
    inventory = ServiceInventoryService(db_path)

    with pytest.raises(ServiceInventoryError):
        inventory.process_result(
            {**network, "enabled": False},
            device,
            result((port(22),)),
        )

    with pytest.raises(ServiceInventoryError):
        inventory.process_result(
            network,
            {**device, "network_id": 99},
            result((port(22),)),
        )