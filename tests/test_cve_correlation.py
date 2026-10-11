from datetime import datetime

from database.changes import list_changes
from database.cves import list_cve_matches
from database.findings import list_findings
from database.inventory import create_device
from database.networks import create_network
from database.services import create_port, create_service
from services.cve_correlation import CveCorrelationService
from services.cve_models import CveRecord, CveServiceEvidence


def setup_context(db_path, version="9.6"):
    network = create_network("192.168.1.0/24", "LAN", "", True, True, db_path)
    device = create_device("network:1:mac:aa:bb:cc:dd:ee:ff", 1, "aa:bb:cc:dd:ee:ff", "server", "Vendor", "2026-10-11T11:59:00", "2026-10-11T11:59:00", "192.168.1.20", "ONLINE", "HIGH", db_path)
    port = create_port(device["id"], 22, "tcp", "open", "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path)
    service = create_service(device["id"], port["id"], "ssh", "OpenSSH", version, None, "HIGH", "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path)
    return network, device, port, service


def evidence(service_id, device_id, port_id, version):
    return CveServiceEvidence(
        service_id=service_id,
        device_id=device_id,
        port_id=port_id,
        product="OpenSSH",
        version=version,
        confidence="HIGH",
        source="nmap-service-discovery",
        observed_at=datetime(2026, 10, 11, 12, 0, 0),
    )


def test_local_cve_correlation_creates_review_and_deduplicates(tmp_path):
    db_path = tmp_path / "test.db"
    network, device, port, service = setup_context(db_path)
    record = CveRecord(
        cve_id="CVE-2099-0001",
        source="local-test-feed",
        product="OpenSSH",
        affected_version_expression=">=9.0,<9.7",
    )
    correlation = CveCorrelationService(db_path)
    first = correlation.correlate(
        evidence(service["id"], device["id"], port["id"], "9.6"),
        [record],
    )
    second = correlation.correlate(
        evidence(service["id"], device["id"], port["id"], "9.6"),
        [record],
    )

    assert first[0]["status"] == "REVIEW"
    assert first[0]["confidence"] == "HIGH"
    assert first[0]["id"] == second[0]["id"]
    assert len(list_cve_matches(db_path)) == 1
    assert len(list_findings(db_path)) == 1
    assert list_findings(db_path)[0]["finding_type"] == "CVE_REVIEW"


def test_version_change_preserves_historical_match_and_records_not_affected(tmp_path):
    db_path = tmp_path / "test.db"
    _, device, port, service = setup_context(db_path)
    record = CveRecord(
        cve_id="CVE-2099-0001",
        source="local-test-feed",
        product="OpenSSH",
        affected_version_expression=">=9.0,<9.7",
    )
    correlation = CveCorrelationService(db_path)
    correlation.correlate(evidence(service["id"], device["id"], port["id"], "9.6"), [record])
    updated = correlation.correlate(evidence(service["id"], device["id"], port["id"], "9.7"), [record])

    assert {match["status"] for match in list_cve_matches(db_path)} == {"REVIEW", "NOT_AFFECTED"}
    assert len(updated) == 1
    assert updated[0]["status"] == "NOT_AFFECTED"
    assert len(list_findings(db_path)) == 1