from datetime import datetime

from database.changes import create_change
from database.findings import get_finding_by_stable_key, list_findings
from database.findings import update_finding_status
from database.inventory import create_device
from database.networks import create_network
from database.services import create_port, create_service
from services.change_models import ChangeRecord
from services.device_inventory import DeviceInventoryService
from services.scan_models import HostDiscoveryResult, ScanResult
from services.risk_engine import RiskEngine
from services.service_inventory import ServiceInventoryService
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)


def setup_context(db_path):
    network = create_network(
        "192.168.1.0/24", "Test LAN", "", True, True, db_path
    )
    device = create_device(
        "network:1:mac:aa:bb:cc:dd:ee:ff",
        network["id"],
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
    return network, device


def test_telnet_and_new_service_findings_are_deduplicated(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_context(db_path)
    port = create_port(
        device["id"], 23, "tcp", "open",
        "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path
    )
    create_service(
        device["id"], port["id"], "telnet", None, None, None, "HIGH",
        "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path
    )
    create_change(
        ChangeRecord(
            change_type="NEW_PORT",
            device_id=device["id"],
            network_id=network["id"],
            port_id=port["id"],
            observed_at=datetime(2026, 10, 11, 12, 0, 0),
            source="service-inventory",
            confidence="HIGH",
            evidence_type="PORT_OBSERVATION",
            message="TCP port 23 was observed for the first time.",
        ),
        db_path,
    )

    engine = RiskEngine(db_path)
    first = engine.evaluate_device(device, network["id"])
    second = engine.evaluate_device(device, network["id"])

    assert len(first) == 2
    assert len(second) == 2
    assert len(list_findings(db_path)) == 2
    assert len(get_finding_by_stable_key(first[0]["stable_key"], db_path)["stable_key"]) > 0


def test_unknown_port_does_not_create_vulnerability_claim(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_context(db_path)
    create_port(
        device["id"], 443, "tcp", "open",
        "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path
    )

    findings = RiskEngine(db_path).evaluate_device(device, network["id"])

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "UNKNOWN_SERVICE_REVIEW"
    assert "vulnerable" not in findings[0]["reason"].lower()


def test_manual_acknowledged_status_is_preserved_on_reevaluation(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_context(db_path)
    port = create_port(
        device["id"], 23, "tcp", "open",
        "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path
    )
    create_service(
        device["id"], port["id"], "telnet", None, None, None, "HIGH",
        "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path
    )
    engine = RiskEngine(db_path)
    finding = engine.evaluate_device(device, network["id"])[0]
    update_finding_status(finding["id"], "ACKNOWLEDGED", db_path=db_path)

    engine.evaluate_device(device, network["id"])

    assert get_finding_by_stable_key(
        finding["stable_key"], db_path
    )["status"] == "ACKNOWLEDGED"


def test_mocked_inventory_to_risk_flow_preserves_evidence(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_network(
        "192.168.1.0/24", "Test LAN", "", True, True, db_path
    )
    host_time = datetime(2026, 10, 11, 12, 0, 0)
    device_scan = ScanResult(
        target_network="192.168.1.0/24",
        scanner="mock-host",
        started_at=host_time,
        completed_at=host_time,
        hosts=(
            HostDiscoveryResult(
                ip_address="192.168.1.20",
                mac_address="aa:bb:cc:dd:ee:ff",
                hostname="server",
                vendor="Vendor",
                discovered_at=host_time,
                source="mock-host",
            ),
        ),
    )
    device = DeviceInventoryService(db_path).process_scan(
        network,
        device_scan,
    )[0]
    service_time = datetime(2026, 10, 11, 12, 1, 0)
    service_result = ServiceDiscoveryResult(
        target_ip="192.168.1.20",
        scanner="mock-service",
        started_at=service_time,
        completed_at=service_time,
        ports=(
            PortObservation(
                ip_address="192.168.1.20",
                port=23,
                transport="tcp",
                state="open",
                observed_at=service_time,
                source="mock-service",
            ),
        ),
        services=(
            ServiceObservation(
                ip_address="192.168.1.20",
                port=23,
                transport="tcp",
                service_name="telnet",
                product=None,
                version=None,
                extra_info=None,
                confidence="HIGH",
                observed_at=service_time,
                source="mock-service",
            ),
        ),
    )

    ServiceInventoryService(db_path).process_result(
        network,
        device,
        service_result,
    )
    findings = RiskEngine(db_path).evaluate_device(device, network["id"])

    assert {finding["finding_type"] for finding in findings} == {
        "PLAINTEXT_SERVICE",
        "NEW_SERVICE_EXPOSURE",
    }
    assert all(finding["rule_id"] for finding in findings)